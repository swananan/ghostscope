//! Variable management for eBPF code generation
//!
//! This module handles variable storage, retrieval, and type tracking.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::VarType;
use inkwell::values::BasicValueEnum;
use inkwell::AddressSpace;
use tracing::{debug, info};

impl<'ctx> EbpfContext<'ctx> {
    /// Store a variable value
    pub fn store_variable(&mut self, name: &str, value: BasicValueEnum<'ctx>) -> Result<()> {
        // Determine variable type from the value
        let var_type = match value {
            BasicValueEnum::IntValue(_) => VarType::Int,
            BasicValueEnum::FloatValue(_) => VarType::Float,
            BasicValueEnum::PointerValue(_) => VarType::String,
            _ => {
                return Err(CodeGenError::TypeError(
                    "Unsupported variable type".to_string(),
                ))
            }
        };

        // Create stack allocation for the variable
        let alloca = match value {
            BasicValueEnum::IntValue(_) => {
                let i64_type = self.context.i64_type();
                self.builder
                    .build_alloca(i64_type, name)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            }
            BasicValueEnum::FloatValue(_) => {
                let f64_type = self.context.f64_type();
                self.builder
                    .build_alloca(f64_type, name)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            }
            BasicValueEnum::PointerValue(_) => {
                let ptr_type = self.context.ptr_type(AddressSpace::default());
                self.builder
                    .build_alloca(ptr_type, name)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            }
            _ => {
                return Err(CodeGenError::TypeError(
                    "Unsupported variable type".to_string(),
                ))
            }
        };

        // Store the value
        self.builder
            .build_store(alloca, value)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Track the variable
        self.variables.insert(name.to_string(), alloca);
        self.var_types.insert(name.to_string(), var_type.clone());

        info!("Stored variable '{}' with type {:?}", name, var_type);
        Ok(())
    }

    /// Retrieve a variable value
    pub fn load_variable(&mut self, name: &str) -> Result<BasicValueEnum<'ctx>> {
        if let Some(alloca) = self.variables.get(name) {
            let var_type = self
                .var_types
                .get(name)
                .ok_or_else(|| CodeGenError::VariableNotFound(name.to_string()))?;

            debug!("Loading variable '{}' with type {:?}", name, var_type);

            let loaded_value = self
                .builder
                .build_load(alloca.get_type(), *alloca, name)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            Ok(loaded_value)
        } else {
            Err(CodeGenError::VariableNotFound(name.to_string()))
        }
    }

    /// Check if a variable exists in the current scope
    pub fn variable_exists(&self, name: &str) -> bool {
        self.variables.contains_key(name)
    }

    /// Get variable type
    pub fn get_variable_type(&self, name: &str) -> Option<&VarType> {
        self.var_types.get(name)
    }

    /// Clear all variables (for new scope)
    pub fn clear_variables(&mut self) {
        debug!("Clearing all variables from scope");
        self.variables.clear();
        self.var_types.clear();
        self.optimized_out_vars.clear();
        self.var_pc_addresses.clear();
    }
}

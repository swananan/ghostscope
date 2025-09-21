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

        // In eBPF, we don't use dynamic stack allocation. Instead, we store variables
        // directly as values and use them when needed. For simple cases, we can just
        // track the value directly.

        // For eBPF compatibility, we store variables as direct values rather than
        // allocating stack space. This works for our current use case where we
        // mainly read variables and send them via ringbuf.

        // Create a global variable if we need persistent storage
        let global_name = format!("_var_{}", name);
        let global_var = match value {
            BasicValueEnum::IntValue(_) => {
                let i64_type = self.context.i64_type();
                let global =
                    self.module
                        .add_global(i64_type, Some(AddressSpace::default()), &global_name);
                global.set_initializer(&i64_type.const_zero());
                global.as_pointer_value()
            }
            BasicValueEnum::FloatValue(_) => {
                let f64_type = self.context.f64_type();
                let global =
                    self.module
                        .add_global(f64_type, Some(AddressSpace::default()), &global_name);
                global.set_initializer(&f64_type.const_zero());
                global.as_pointer_value()
            }
            BasicValueEnum::PointerValue(_) => {
                let ptr_type = self.context.ptr_type(AddressSpace::default());
                let global =
                    self.module
                        .add_global(ptr_type, Some(AddressSpace::default()), &global_name);
                global.set_initializer(&ptr_type.const_null());
                global.as_pointer_value()
            }
            _ => {
                return Err(CodeGenError::TypeError(
                    "Unsupported variable type".to_string(),
                ))
            }
        };

        // Store the value in the global variable
        self.builder
            .build_store(global_var, value)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Track the variable
        self.variables.insert(name.to_string(), global_var);
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

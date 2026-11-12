//! Variable management for eBPF code generation
//!
//! This module handles variable storage, retrieval, and type tracking.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::VarType;
use inkwell::values::BasicValueEnum;
use tracing::{debug, info};

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Register a DWARF alias variable. The value expression is stored and resolved at use time.
    pub fn set_alias_variable(&mut self, name: &str, expr: crate::script::Expr) {
        self.alias_vars.insert(name.to_string(), expr);
        // Ensure any previous concrete variable storage is cleared to avoid confusion
        self.variables.remove(name);
        self.var_types.remove(name);
        self.optimized_out_vars.remove(name);
        self.var_pc_addresses.remove(name);
        self.string_vars.remove(name);
    }

    /// Check whether an alias variable exists
    pub fn alias_variable_exists(&self, name: &str) -> bool {
        self.alias_vars.contains_key(name)
    }

    /// Get a clone of the stored alias expression if present
    pub fn get_alias_variable(&self, name: &str) -> Option<crate::script::Expr> {
        self.alias_vars.get(name).cloned()
    }
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

        // Script bindings are immutable and lexically scoped. Keep the SSA value
        // produced by this invocation instead of round-tripping through .bss.
        self.variables.insert(name.to_string(), value);
        self.var_types.insert(name.to_string(), var_type.clone());

        info!(
            "store_variable: Stored variable '{}' with type {:?}",
            name, var_type
        );
        debug!("store_variable: Value type stored: {:?}", value.get_type());
        match &value {
            BasicValueEnum::IntValue(iv) => debug!(
                "store_variable: Stored IntValue with bit width {}",
                iv.get_type().get_bit_width()
            ),
            BasicValueEnum::FloatValue(_) => debug!("store_variable: Stored FloatValue"),
            BasicValueEnum::PointerValue(_) => debug!("store_variable: Stored PointerValue"),
            _ => debug!("store_variable: Stored other type"),
        }
        Ok(())
    }

    /// Retrieve a variable value
    pub fn load_variable(&mut self, name: &str) -> Result<BasicValueEnum<'ctx>> {
        self.variables
            .get(name)
            .copied()
            .ok_or_else(|| CodeGenError::VariableNotFound(name.to_string()))
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
        self.alias_vars.clear();
        self.string_vars.clear();
    }

    /// Register a string variable's bytes (including optional NUL terminator)
    pub fn set_string_variable_bytes(&mut self, name: &str, bytes: Vec<u8>) {
        self.string_vars.insert(name.to_string(), bytes);
        // String vars are concrete script variables of VarType::String; no alias
        self.alias_vars.remove(name);
    }

    /// Get string variable bytes if present
    pub fn get_string_variable_bytes(&self, name: &str) -> Option<&Vec<u8>> {
        self.string_vars.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_bindings_preserve_values_and_widths_across_branches() {
        let context = inkwell::context::Context::create();
        let options = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "bindings", Some(0), &options).unwrap();
        ctx.create_basic_ebpf_function("probe").unwrap();
        let function = ctx.current_function("test").unwrap();
        let values = [
            context.bool_type().const_int(1, false).into(),
            context.i8_type().const_int(42, false).into(),
            context.i64_type().const_int(123, false).into(),
            context.f64_type().const_float(1.5).into(),
            function.get_first_param().unwrap(),
        ];
        ctx.enter_scope();
        for (i, value) in values.iter().enumerate() {
            let name = format!("v{i}");
            ctx.declare_name_in_current_scope(&name).unwrap();
            ctx.store_variable(&name, *value).unwrap();
        }
        let body = context.append_basic_block(function, "body");
        ctx.builder.build_unconditional_branch(body).unwrap();
        ctx.builder.position_at_end(body);
        ctx.enter_scope();
        ctx.declare_name_in_current_scope("inner").unwrap();
        ctx.store_variable("inner", values[0]).unwrap();
        ctx.exit_scope();
        assert!(ctx.load_variable("inner").is_err());
        for (i, value) in values.iter().enumerate() {
            assert_eq!(ctx.load_variable(&format!("v{i}")).unwrap(), *value);
        }
        ctx.exit_scope();
        assert!(ctx.load_variable("v0").is_err());
        ctx.builder
            .build_return(Some(&context.i32_type().const_zero()))
            .unwrap();
        ctx.module.verify().unwrap();
        assert!(!ctx.module.print_to_string().to_string().contains("@_var_"));
    }
}

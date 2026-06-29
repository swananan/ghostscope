use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Resolve variable with correct priority: script variables first, then DWARF variables
    /// This method is copied from protocol.rs to maintain functionality
    pub fn resolve_variable_with_priority(&mut self, var_name: &str) -> Result<(u16, TypeKind)> {
        info!("Resolving variable '{}' with correct priority", var_name);

        // Step 1: Check if it's a script-defined variable first
        if self.variable_exists(var_name) {
            info!("Found script variable: {}", var_name);

            // Get the variable's LLVM value to infer type
            let loaded_value = self.load_variable(var_name)?;
            let type_encoding = self.infer_type_from_llvm_value(&loaded_value);

            // Add to TraceContext
            let var_name_index = self.trace_context.add_variable_name(var_name.to_string())?;

            return Ok((var_name_index, type_encoding));
        }

        // Step 2: If not found in script variables, try DWARF variables
        info!(
            "Variable '{}' not found in script variables, checking DWARF",
            var_name
        );

        let compile_context = self.get_compile_time_context()?.clone();
        let read_plan = match self.query_dwarf_for_variable(var_name)? {
            Some(var) => var,
            None => {
                return Err(CodeGenError::VariableNotFound(format!(
                    "Variable '{}' not found in script or DWARF at PC 0x{:x} in module '{}'",
                    var_name, compile_context.pc_address, compile_context.module_path
                )));
            }
        };

        // Convert DWARF type information to TypeKind using existing method
        let dwarf_type = read_plan.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Variable has no DWARF type information".to_string())
        })?;
        let type_encoding = TypeKind::from(dwarf_type);

        // Add to StringTable
        let var_name_index = self.trace_context.add_variable_name(var_name.to_string())?;

        info!(
            "DWARF variable '{}' resolved successfully with type: {:?}",
            var_name, type_encoding
        );

        Ok((var_name_index, type_encoding))
    }

    /// Synthesize a DWARF-like TypeInfo for a basic TypeKind (for script variables)
    pub(super) fn synthesize_typeinfo_for_typekind(
        &self,
        kind: TypeKind,
    ) -> ghostscope_dwarf::TypeInfo {
        use ghostscope_dwarf::constants::{
            DW_ATE_boolean, DW_ATE_float, DW_ATE_signed, DW_ATE_signed_char, DW_ATE_unsigned,
        };
        use ghostscope_dwarf::TypeInfo as TI;

        match kind {
            TypeKind::Bool => TI::BaseType {
                name: "bool".to_string(),
                size: 1,
                encoding: DW_ATE_boolean.0 as u16,
            },
            TypeKind::F32 => TI::BaseType {
                name: "f32".to_string(),
                size: 4,
                encoding: DW_ATE_float.0 as u16,
            },
            TypeKind::F64 => TI::BaseType {
                name: "f64".to_string(),
                size: 8,
                encoding: DW_ATE_float.0 as u16,
            },
            TypeKind::I8 => TI::BaseType {
                name: "i8".to_string(),
                size: 1,
                encoding: DW_ATE_signed_char.0 as u16,
            },
            TypeKind::I16 => TI::BaseType {
                name: "i16".to_string(),
                size: 2,
                encoding: DW_ATE_signed.0 as u16,
            },
            TypeKind::I32 => TI::BaseType {
                name: "i32".to_string(),
                size: 4,
                encoding: DW_ATE_signed.0 as u16,
            },
            TypeKind::I64 => TI::BaseType {
                name: "i64".to_string(),
                size: 8,
                encoding: DW_ATE_signed.0 as u16,
            },
            TypeKind::U8 | TypeKind::Char => TI::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::U16 => TI::BaseType {
                name: "u16".to_string(),
                size: 2,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::U32 => TI::BaseType {
                name: "u32".to_string(),
                size: 4,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::U64 => TI::BaseType {
                name: "u64".to_string(),
                size: 8,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::Pointer | TypeKind::CString | TypeKind::String | TypeKind::Unknown => {
                // Use void* as a reasonable default for pointers/strings in script land
                TI::PointerType {
                    target_type: Box::new(TI::UnknownType {
                        name: "void".to_string(),
                    }),
                    size: 8,
                }
            }
            TypeKind::NullPointer => TI::PointerType {
                target_type: Box::new(TI::UnknownType {
                    name: "void".to_string(),
                }),
                size: 8,
            },
            _ => TI::BaseType {
                name: "i64".to_string(),
                size: 8,
                encoding: DW_ATE_signed.0 as u16,
            },
        }
    }

    pub(super) fn add_synthesized_type_index_for_kind(&mut self, kind: TypeKind) -> Result<u16> {
        let ti = self.synthesize_typeinfo_for_typekind(kind);
        Ok(self.trace_context.add_type(ti)?)
    }

    /// Infer TypeKind from LLVM value type
    /// Copied from protocol.rs
    pub(super) fn infer_type_from_llvm_value(&self, value: &BasicValueEnum<'_>) -> TypeKind {
        match value {
            BasicValueEnum::IntValue(int_val) => {
                match int_val.get_type().get_bit_width() {
                    1 => TypeKind::Bool,
                    8 => TypeKind::I8, // Default to signed for script variables
                    16 => TypeKind::I16,
                    32 => TypeKind::I32,
                    64 => TypeKind::I64,
                    _ => TypeKind::I64, // Default fallback
                }
            }
            BasicValueEnum::FloatValue(float_val) => {
                match float_val.get_type() {
                    t if t == self.context.f32_type() => TypeKind::F32,
                    t if t == self.context.f64_type() => TypeKind::F64,
                    _ => TypeKind::F64, // Default fallback
                }
            }
            BasicValueEnum::PointerValue(_) => TypeKind::Pointer,
            _ => TypeKind::I64, // Conservative default
        }
    }
}

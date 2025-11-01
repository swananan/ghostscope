//! Code generation for instructions
//!
//! This module handles the conversion from statements to compiled instructions
//! and generates LLVM IR for individual instructions.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::{PrintStatement, Program, Statement};
use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user;
use ghostscope_protocol::trace_event::{
    BacktraceData, InstructionHeader, PrintComplexVariableData, PrintStringIndexData,
    PrintVariableIndexData, VariableStatus,
};
use ghostscope_protocol::{InstructionType, TraceContext, TypeKind};
use inkwell::values::{BasicValueEnum, IntValue};
use inkwell::AddressSpace;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Parameters for generating a PrintComplexVariable with runtime read
#[derive(Debug, Clone)]
struct PrintVarRuntimeMeta {
    var_name_index: u16,
    type_index: u16,
    access_path: String,
    data_len_limit: usize,
}

/// Source for complex formatted argument data
#[derive(Debug, Clone)]
enum ComplexArgSource<'ctx> {
    RuntimeRead {
        eval_result: ghostscope_dwarf::EvaluationResult,
        dwarf_type: ghostscope_dwarf::TypeInfo,
        module_for_offsets: Option<String>,
    },
    /// Memory dump from a pointer/byte address with a static length
    MemDump {
        src_addr: inkwell::values::IntValue<'ctx>,
        len: usize,
    },
    /// Memory dump with dynamic runtime length; bytes read up to min(len_value, max_len)
    MemDumpDynamic {
        src_addr: inkwell::values::IntValue<'ctx>,
        len_value: inkwell::values::IntValue<'ctx>,
        max_len: usize,
    },
    ImmediateBytes {
        bytes: Vec<u8>,
    },
    AddressValue {
        eval_result: ghostscope_dwarf::EvaluationResult,
        module_for_offsets: Option<String>,
    },
    // Newly added: a value computed in LLVM at runtime (e.g., expression result)
    ComputedInt {
        value: inkwell::values::IntValue<'ctx>,
        byte_len: usize, // typically 8
    },
}

/// Argument descriptor for PrintComplexFormat
#[derive(Debug, Clone)]
struct ComplexArg<'ctx> {
    var_name_index: u16,
    type_index: u16,
    access_path: Vec<u8>,
    data_len: usize,
    source: ComplexArgSource<'ctx>,
}

impl<'ctx> EbpfContext<'ctx> {
    /// Unified expression resolver: returns a ComplexArg carrying
    /// a consistent var_name_index/type_index/access_path/data_len/source
    /// with strict priority: script variables -> DWARF (locals/params/globals).
    fn resolve_expr_to_arg(&mut self, expr: &crate::script::ast::Expr) -> Result<ComplexArg<'ctx>> {
        use crate::script::ast::Expr as E;
        match expr {
            // 0) Alias variables: resolve to address and render as pointer value
            E::Variable(name) if self.alias_variable_exists(name) => {
                let aliased = self.get_alias_variable(name).expect("alias exists");
                let addr_i64 = self.resolve_ptr_i64_from_expr(&aliased)?;
                let var_name_index = self.trace_context.add_variable_name(name.clone());
                Ok(ComplexArg {
                    var_name_index,
                    type_index: self.add_synthesized_type_index_for_kind(TypeKind::Pointer),
                    access_path: Vec::new(),
                    data_len: 8,
                    source: ComplexArgSource::ComputedInt {
                        value: addr_i64,
                        byte_len: 8,
                    },
                })
            }
            // 1) Script variables first
            E::Variable(name) if self.variable_exists(name) => {
                let val = self.load_variable(name)?;
                let var_name_index = self.trace_context.add_variable_name(name.clone());
                // If this is a string variable, print its contents instead of address
                if self
                    .get_variable_type(name)
                    .is_some_and(|t| matches!(t, crate::script::VarType::String))
                {
                    let bytes_opt = self.get_string_variable_bytes(name).cloned();
                    if let Some(bytes) = bytes_opt {
                        // Build a char[] type with length=bytes.len()
                        let char_type = ghostscope_dwarf::TypeInfo::BaseType {
                            name: "char".to_string(),
                            size: 1,
                            encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char.0 as u16,
                        };
                        let array_type = ghostscope_dwarf::TypeInfo::ArrayType {
                            element_type: Box::new(char_type),
                            element_count: Some(bytes.len() as u64),
                            total_size: Some(bytes.len() as u64),
                        };
                        return Ok(ComplexArg {
                            var_name_index,
                            type_index: self.trace_context.add_type(array_type),
                            access_path: Vec::new(),
                            data_len: bytes.len(),
                            source: ComplexArgSource::ImmediateBytes { bytes },
                        });
                    }
                }
                match val {
                    BasicValueEnum::IntValue(iv) => {
                        // Preserve signedness for display: map bit width to I8/I16/I32/I64
                        let bitw = iv.get_type().get_bit_width();
                        let (kind, byte_len) = if bitw == 1 {
                            (TypeKind::Bool, 1)
                        } else if bitw <= 8 {
                            (TypeKind::I8, 1)
                        } else if bitw <= 16 {
                            (TypeKind::I16, 2)
                        } else if bitw <= 32 {
                            (TypeKind::I32, 4)
                        } else {
                            (TypeKind::I64, 8)
                        };
                        Ok(ComplexArg {
                            var_name_index,
                            type_index: self.add_synthesized_type_index_for_kind(kind),
                            access_path: Vec::new(),
                            data_len: byte_len,
                            source: ComplexArgSource::ComputedInt {
                                value: iv,
                                byte_len,
                            },
                        })
                    }
                    BasicValueEnum::PointerValue(pv) => {
                        // Non-string pointer variable: print as address (hex)
                        let iv = self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        Ok(ComplexArg {
                            var_name_index,
                            type_index: self.add_synthesized_type_index_for_kind(TypeKind::Pointer),
                            access_path: Vec::new(),
                            data_len: 8,
                            source: ComplexArgSource::ComputedInt {
                                value: iv,
                                byte_len: 8,
                            },
                        })
                    }
                    _ => Err(CodeGenError::TypeError(
                        "Unsupported script variable type for print".to_string(),
                    )),
                }
            }

            // 2) String literal -> Immediate bytes (for formatted args)
            E::String(s) => {
                let mut bytes = s.as_bytes().to_vec();
                bytes.push(0);
                let char_type = ghostscope_dwarf::TypeInfo::BaseType {
                    name: "char".to_string(),
                    size: 1,
                    encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char.0 as u16,
                };
                let array_type = ghostscope_dwarf::TypeInfo::ArrayType {
                    element_type: Box::new(char_type),
                    element_count: Some(bytes.len() as u64),
                    total_size: Some(bytes.len() as u64),
                };
                Ok(ComplexArg {
                    var_name_index: self
                        .trace_context
                        .add_variable_name("__str_literal".to_string()),
                    type_index: self.trace_context.add_type(array_type),
                    access_path: Vec::new(),
                    data_len: bytes.len(),
                    source: ComplexArgSource::ImmediateBytes { bytes },
                })
            }

            // 3) Integer literal -> Immediate i64 bytes
            E::Int(v) => {
                let mut bytes = Vec::with_capacity(8);
                bytes.extend_from_slice(&(*v).to_le_bytes());
                let int_type = ghostscope_dwarf::TypeInfo::BaseType {
                    name: "i64".to_string(),
                    size: 8,
                    encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
                };
                Ok(ComplexArg {
                    var_name_index: self
                        .trace_context
                        .add_variable_name("__int_literal".to_string()),
                    type_index: self.trace_context.add_type(int_type),
                    access_path: Vec::new(),
                    data_len: 8,
                    source: ComplexArgSource::ImmediateBytes { bytes },
                })
            }

            // 4) AddressOf: return AddressValue (pointer payload will be produced)
            E::AddressOf(inner) => {
                let var = self
                    .query_dwarf_for_complex_expr(inner)?
                    .ok_or_else(|| CodeGenError::VariableNotFound(format!("{inner:?}")))?;
                let inner_ty = var.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
                })?;
                let ptr_ty = ghostscope_dwarf::TypeInfo::PointerType {
                    target_type: Box::new(inner_ty.clone()),
                    size: 8,
                };
                let module_hint = self.take_module_hint();
                Ok(ComplexArg {
                    var_name_index: self
                        .trace_context
                        .add_variable_name(self.expr_to_name(expr)),
                    type_index: self.trace_context.add_type(ptr_ty),
                    access_path: Vec::new(),
                    data_len: 8,
                    source: ComplexArgSource::AddressValue {
                        eval_result: var.evaluation_result.clone(),
                        module_for_offsets: module_hint,
                    },
                })
            }

            // 5) Complex lvalue shapes -> DWARF runtime read
            expr @ (E::MemberAccess(_, _)
            | E::ArrayAccess(_, _)
            | E::PointerDeref(_)
            | E::ChainAccess(_)) => {
                let var = self
                    .query_dwarf_for_complex_expr(expr)?
                    .ok_or_else(|| CodeGenError::VariableNotFound(format!("{expr:?}")))?;
                if matches!(
                    var.evaluation_result,
                    ghostscope_dwarf::EvaluationResult::Optimized
                ) {
                    let ti = ghostscope_protocol::type_info::TypeInfo::OptimizedOut {
                        name: var.name.clone(),
                    };
                    return Ok(ComplexArg {
                        var_name_index: self.trace_context.add_variable_name(var.name.clone()),
                        type_index: self.trace_context.add_type(ti),
                        access_path: Vec::new(),
                        data_len: 0,
                        source: ComplexArgSource::ImmediateBytes { bytes: Vec::new() },
                    });
                }
                let dwarf_type = var.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
                })?;
                let data_len = Self::compute_read_size_for_type(dwarf_type);
                if data_len == 0 {
                    return Err(CodeGenError::TypeSizeNotAvailable(var.name));
                }
                // Previously clamped to 1993 bytes; now use full DWARF size (transport clamps per event size)
                // data_len unchanged
                let module_hint = self.take_module_hint();
                Ok(ComplexArg {
                    var_name_index: self.trace_context.add_variable_name(var.name.clone()),
                    type_index: self.trace_context.add_type(dwarf_type.clone()),
                    access_path: Vec::new(),
                    data_len,
                    source: ComplexArgSource::RuntimeRead {
                        eval_result: var.evaluation_result.clone(),
                        dwarf_type: dwarf_type.clone(),
                        module_for_offsets: module_hint,
                    },
                })
            }

            // 6) Variable not in script scope → DWARF variable or computed fast-path for simple scalars
            E::Variable(name) => {
                if let Some(v) = self.query_dwarf_for_variable(name)? {
                    if let Some(ref t) = v.dwarf_type {
                        // If DWARF reports optimized-out at this PC, emit OptimizedOut type with no data
                        if matches!(
                            v.evaluation_result,
                            ghostscope_dwarf::EvaluationResult::Optimized
                        ) {
                            let ti = ghostscope_protocol::type_info::TypeInfo::OptimizedOut {
                                name: v.name.clone(),
                            };
                            return Ok(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(v.name.clone()),
                                type_index: self.trace_context.add_type(ti),
                                access_path: Vec::new(),
                                data_len: 0,
                                source: ComplexArgSource::ImmediateBytes { bytes: Vec::new() },
                            });
                        }
                        let is_link_addr = matches!(
                            v.evaluation_result,
                            ghostscope_dwarf::EvaluationResult::MemoryLocation(
                                ghostscope_dwarf::LocationResult::Address(_)
                            )
                        );
                        if Self::is_simple_typeinfo(t) && !is_link_addr {
                            // Prefer computed value to avoid runtime reads
                            let compiled = self.compile_expr(expr)?;
                            match compiled {
                                BasicValueEnum::IntValue(iv) => {
                                    // Respect DWARF pointer types to keep pointer formatting
                                    let (kind, byte_len) = if matches!(
                                        t,
                                        ghostscope_dwarf::TypeInfo::PointerType { .. }
                                    ) {
                                        (TypeKind::Pointer, 8)
                                    } else {
                                        let bitw = iv.get_type().get_bit_width();
                                        if bitw == 1 {
                                            (TypeKind::Bool, 1)
                                        } else if bitw <= 8 {
                                            (TypeKind::I8, 1)
                                        } else if bitw <= 16 {
                                            (TypeKind::I16, 2)
                                        } else if bitw <= 32 {
                                            (TypeKind::I32, 4)
                                        } else {
                                            (TypeKind::I64, 8)
                                        }
                                    };
                                    Ok(ComplexArg {
                                        var_name_index: self
                                            .trace_context
                                            .add_variable_name(self.expr_to_name(expr)),
                                        type_index: self.add_synthesized_type_index_for_kind(kind),
                                        access_path: Vec::new(),
                                        data_len: byte_len,
                                        source: ComplexArgSource::ComputedInt {
                                            value: iv,
                                            byte_len,
                                        },
                                    })
                                }
                                BasicValueEnum::PointerValue(pv) => {
                                    // Pointer register-backed → cast to i64 with pointer typeindex
                                    let iv = self
                                        .builder
                                        .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                                    Ok(ComplexArg {
                                        var_name_index: self
                                            .trace_context
                                            .add_variable_name(self.expr_to_name(expr)),
                                        type_index: self
                                            .add_synthesized_type_index_for_kind(TypeKind::Pointer),
                                        access_path: Vec::new(),
                                        data_len: 8,
                                        source: ComplexArgSource::ComputedInt {
                                            value: iv,
                                            byte_len: 8,
                                        },
                                    })
                                }
                                _ => {
                                    // Fall back to runtime read path
                                    let data_len = Self::compute_read_size_for_type(t);
                                    if data_len == 0 {
                                        return Err(CodeGenError::TypeSizeNotAvailable(v.name));
                                    }
                                    // Remove legacy 1993-byte clamp; keep DWARF-reported size
                                    let module_hint = self.take_module_hint();
                                    Ok(ComplexArg {
                                        var_name_index: self
                                            .trace_context
                                            .add_variable_name(v.name.clone()),
                                        type_index: self.trace_context.add_type(t.clone()),
                                        access_path: Vec::new(),
                                        data_len,
                                        source: ComplexArgSource::RuntimeRead {
                                            eval_result: v.evaluation_result.clone(),
                                            dwarf_type: t.clone(),
                                            module_for_offsets: module_hint,
                                        },
                                    })
                                }
                            }
                        } else {
                            // Complex types or link-time addresses: use RuntimeRead
                            // (globals/statics need memory read; not an address print unless AddressOf)
                            let data_len = Self::compute_read_size_for_type(t);
                            if data_len == 0 {
                                return Err(CodeGenError::TypeSizeNotAvailable(v.name));
                            }
                            // Remove legacy 1993-byte clamp; keep DWARF-reported size
                            let module_hint = self.take_module_hint();
                            Ok(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(v.name.clone()),
                                type_index: self.trace_context.add_type(t.clone()),
                                access_path: Vec::new(),
                                data_len,
                                source: ComplexArgSource::RuntimeRead {
                                    eval_result: v.evaluation_result.clone(),
                                    dwarf_type: t.clone(),
                                    module_for_offsets: module_hint,
                                },
                            })
                        }
                    } else {
                        Err(CodeGenError::DwarfError(
                            "Variable has no DWARF type information".to_string(),
                        ))
                    }
                } else {
                    Err(CodeGenError::VariableNotInScope(name.clone()))
                }
            }

            // 7) Pointer arithmetic (ptr +/- K) → typed runtime read at computed address
            E::BinaryOp { left, op, right } => {
                use crate::script::ast::BinaryOp as BO;
                // Support: ptr + int, int + ptr, ptr - int (int may be negative)
                // Only allow when ptr side resolves to DWARF pointer/array; the offset must be an integer literal for now.
                // We emit a RuntimeRead with computed location, preserving the pointed-to DWARF type.
                let (ptr_side, int_side, sign) = match (&**left, op, &**right) {
                    (l, BO::Add, E::Int(k)) => (l, *k, 1),
                    (E::Int(k), BO::Add, r) => (r, *k, 1),
                    (l, BO::Subtract, E::Int(k)) => (l, *k, -1),
                    _ => {
                        // Fallback to generic expression handling below
                        let compiled = self.compile_expr(expr)?;
                        if let BasicValueEnum::IntValue(iv) = compiled {
                            let bitw = iv.get_type().get_bit_width();
                            let (kind, byte_len) = if bitw == 1 {
                                (TypeKind::Bool, 1)
                            } else if bitw <= 8 {
                                (TypeKind::I8, 1)
                            } else if bitw <= 16 {
                                (TypeKind::I16, 2)
                            } else if bitw <= 32 {
                                (TypeKind::I32, 4)
                            } else {
                                (TypeKind::I64, 8)
                            };
                            return Ok(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(expr)),
                                type_index: self.add_synthesized_type_index_for_kind(kind),
                                access_path: Vec::new(),
                                data_len: byte_len,
                                source: ComplexArgSource::ComputedInt {
                                    value: iv,
                                    byte_len,
                                },
                            });
                        } else {
                            return Err(CodeGenError::TypeError(
                                "Non-integer expression not supported in print".to_string(),
                            ));
                        }
                    }
                };

                // Try DWARF resolution for the pointer side
                if let Some(var) = self.query_dwarf_for_complex_expr(ptr_side)? {
                    if var.dwarf_type.is_some() {
                        // Determine pointed-to/element type and compute location with scaled offset
                        let index = sign * int_side;
                        let (eval_result, elem_ty) =
                            self.compute_pointed_location_with_index(ptr_side, index)?;
                        let data_len = Self::compute_read_size_for_type(&elem_ty);
                        let module_hint = self.take_module_hint();
                        if data_len == 0 {
                            // Fallback for unsized/void targets: print computed address as pointer
                            let ptr_ti = ghostscope_dwarf::TypeInfo::PointerType {
                                target_type: Box::new(elem_ty.clone()),
                                size: 8,
                            };
                            return Ok(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(expr)),
                                type_index: self.trace_context.add_type(ptr_ti),
                                access_path: Vec::new(),
                                data_len: 8,
                                source: ComplexArgSource::AddressValue {
                                    eval_result,
                                    module_for_offsets: module_hint,
                                },
                            });
                        }
                        return Ok(ComplexArg {
                            var_name_index: self
                                .trace_context
                                .add_variable_name(self.expr_to_name(expr)),
                            type_index: self.trace_context.add_type(elem_ty.clone()),
                            access_path: Vec::new(),
                            data_len,
                            source: ComplexArgSource::RuntimeRead {
                                eval_result,
                                dwarf_type: elem_ty,
                                module_for_offsets: module_hint,
                            },
                        });
                    }
                }

                // If pointer side cannot be resolved as DWARF pointer/array, fall back to computed int
                let compiled = self.compile_expr(expr)?;
                if let BasicValueEnum::IntValue(iv) = compiled {
                    let bitw = iv.get_type().get_bit_width();
                    let (kind, byte_len) = if bitw == 1 {
                        (TypeKind::Bool, 1)
                    } else if bitw <= 8 {
                        (TypeKind::I8, 1)
                    } else if bitw <= 16 {
                        (TypeKind::I16, 2)
                    } else if bitw <= 32 {
                        (TypeKind::I32, 4)
                    } else {
                        (TypeKind::I64, 8)
                    };
                    Ok(ComplexArg {
                        var_name_index: self
                            .trace_context
                            .add_variable_name(self.expr_to_name(expr)),
                        type_index: self.add_synthesized_type_index_for_kind(kind),
                        access_path: Vec::new(),
                        data_len: byte_len,
                        source: ComplexArgSource::ComputedInt {
                            value: iv,
                            byte_len,
                        },
                    })
                } else {
                    Err(CodeGenError::TypeError(
                        "Non-integer expression not supported in print".to_string(),
                    ))
                }
            }

            // Binary and other rvalue expressions → compile to computed int
            other => {
                let compiled = self.compile_expr(other)?;
                if let BasicValueEnum::IntValue(iv) = compiled {
                    let bitw = iv.get_type().get_bit_width();
                    let (kind, byte_len) = if bitw == 1 {
                        (TypeKind::Bool, 1)
                    } else if bitw <= 8 {
                        (TypeKind::I8, 1)
                    } else if bitw <= 16 {
                        (TypeKind::I16, 2)
                    } else if bitw <= 32 {
                        (TypeKind::I32, 4)
                    } else {
                        (TypeKind::I64, 8)
                    };
                    Ok(ComplexArg {
                        var_name_index: self
                            .trace_context
                            .add_variable_name(self.expr_to_name(other)),
                        type_index: self.add_synthesized_type_index_for_kind(kind),
                        access_path: Vec::new(),
                        data_len: byte_len,
                        source: ComplexArgSource::ComputedInt {
                            value: iv,
                            byte_len,
                        },
                    })
                } else {
                    Err(CodeGenError::TypeError(
                        "Non-integer expression not supported in print".to_string(),
                    ))
                }
            }
        }
    }

    /// Emit a single PrintComplexVariable or a single-arg PrintComplexFormat depending on the arg source.
    fn emit_print_from_arg(&mut self, arg: ComplexArg<'ctx>) -> Result<u16> {
        match arg.source {
            ComplexArgSource::ComputedInt { value, byte_len } => {
                self.generate_print_complex_variable_computed(
                    arg.var_name_index,
                    arg.type_index,
                    byte_len,
                    value,
                )?;
                Ok(1)
            }
            ComplexArgSource::RuntimeRead {
                eval_result,
                ref dwarf_type,
                module_for_offsets,
            } => {
                let meta = PrintVarRuntimeMeta {
                    var_name_index: arg.var_name_index,
                    type_index: arg.type_index,
                    access_path: String::new(),
                    data_len_limit: arg.data_len,
                };
                self.generate_print_complex_variable_runtime(
                    meta,
                    &eval_result,
                    dwarf_type,
                    module_for_offsets.as_deref(),
                )?;
                Ok(1)
            }
            ComplexArgSource::AddressValue { .. } | ComplexArgSource::ImmediateBytes { .. } => {
                // Use ComplexFormat with "{}" to render address/immediate nicely
                let fmt_idx = self.trace_context.add_string("{}".to_string());
                self.generate_print_complex_format_instruction(fmt_idx, &[arg])?;
                Ok(1)
            }
            ComplexArgSource::MemDump { .. } | ComplexArgSource::MemDumpDynamic { .. } => {
                // Use ComplexFormat with "{}"; generate_print_complex_format_instruction handles MemDump
                let fmt_idx = self.trace_context.add_string("{}".to_string());
                self.generate_print_complex_format_instruction(fmt_idx, &[arg])?;
                Ok(1)
            }
        }
    }
    /// Generate PrintComplexVariable instruction that embeds a computed integer value (no runtime read)
    /// This is used for `print expr;` where expr is an rvalue computed in eBPF.
    fn generate_print_complex_variable_computed(
        &mut self,
        var_name_index: u16,
        type_index: u16,
        byte_len: usize,
        value: IntValue<'ctx>,
    ) -> Result<()> {
        // Build sizes
        let header_size = std::mem::size_of::<InstructionHeader>();
        let data_struct_size = std::mem::size_of::<PrintComplexVariableData>();
        let access_path_len: usize = 0; // computed expr has no access path
        let total_data_length = data_struct_size + access_path_len + byte_len;
        let total_size = header_size + total_data_length;

        // Reserve space directly in the per-CPU accumulation buffer
        let inst_buffer = self.reserve_instruction_region(total_size as u64);

        // Write InstructionHeader.inst_type
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // Write data_length (u16) at offset 1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        self.builder
            .build_store(
                data_length_ptr_cast,
                self.context
                    .i16_type()
                    .const_int(total_data_length as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Data pointer (after header)
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(header_size as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {e}")))?
        };

        // var_name_index (u16)
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(var_name_index as u64, false);
        let var_name_index_off =
            std::mem::offset_of!(PrintComplexVariableData, var_name_index) as u64;
        let var_name_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(var_name_index_off, false)],
                    "var_name_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {e}"))
                })?
        };
        let var_name_index_ptr_i16 = self
            .builder
            .build_pointer_cast(
                var_name_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {e}"))
            })?;
        self.builder
            .build_store(var_name_index_ptr_i16, var_name_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store var_name_index: {e}")))?;

        // type_index (u16)
        let type_index_offset = std::mem::offset_of!(PrintComplexVariableData, type_index) as u64;
        let type_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(type_index_offset, false)],
                    "type_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {e}"))
                })?
        };
        let type_index_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {e}")))?;
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {e}")))?;

        // access_path_len (u8) = 0
        let access_path_len_off =
            std::mem::offset_of!(PrintComplexVariableData, access_path_len) as u64;
        let access_path_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len_off, false)],
                    "access_path_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {e}"))
                })?
        };
        self.builder
            .build_store(access_path_len_ptr, self.context.i8_type().const_zero())
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {e}"))
            })?;

        // status (u8) = 0
        let status_off = std::mem::offset_of!(PrintComplexVariableData, status) as u64;
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(status_off, false)],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {e}")))?
        };
        self.builder
            .build_store(status_ptr, self.context.i8_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

        // data_len (u16)
        let data_len_off = std::mem::offset_of!(PrintComplexVariableData, data_len) as u64;
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(data_len_off, false)],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data_len GEP: {e}")))?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {e}")))?;
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(byte_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;

        // variable data starts right after PrintComplexVariableData (no access path)
        let var_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(data_struct_size as u64, false)],
                    "var_data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get var_data GEP: {e}")))?
        };

        // Store computed integer value into payload according to byte_len
        match byte_len {
            1 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw == 1 {
                    // Booleans must serialize as 0/1
                    self.builder
                        .build_int_z_extend(value, self.context.i8_type(), "expr_zext_bool_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw < 8 {
                    self.builder
                        .build_int_s_extend(value, self.context.i8_type(), "expr_sext_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 8 {
                    self.builder
                        .build_int_truncate(value, self.context.i8_type(), "expr_trunc_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                self.builder
                    .build_store(var_data_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            2 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw < 16 {
                    self.builder
                        .build_int_s_extend(value, self.context.i16_type(), "expr_sext_i16")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 16 {
                    self.builder
                        .build_int_truncate(value, self.context.i16_type(), "expr_trunc_i16")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i16_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i16_ptr_ty, "expr_i16_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            4 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw < 32 {
                    self.builder
                        .build_int_s_extend(value, self.context.i32_type(), "expr_sext_i32")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 32 {
                    self.builder
                        .build_int_truncate(value, self.context.i32_type(), "expr_trunc_i32")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i32_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i32_ptr_ty, "expr_i32_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            8 => {
                let v64 = if value.get_type().get_bit_width() < 64 {
                    self.builder
                        .build_int_s_extend(value, self.context.i64_type(), "expr_sext_i64")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i64_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i64_ptr_ty, "expr_i64_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v64)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            n => {
                // Fallback: write lowest n bytes little-endian
                let v64 = if value.get_type().get_bit_width() < 64 {
                    self.builder
                        .build_int_s_extend(value, self.context.i64_type(), "expr_sext_fallback")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                for i in 0..n {
                    let shift = self.context.i64_type().const_int((i * 8) as u64, false);
                    let shifted = self
                        .builder
                        .build_right_shift(v64, shift, false, &format!("expr_shr_{i}"))
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let byte = self
                        .builder
                        .build_int_truncate(
                            shifted,
                            self.context.i8_type(),
                            &format!("expr_byte_{i}"),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let byte_ptr = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[self.context.i32_type().const_int(i as u64, false)],
                                &format!("expr_byte_ptr_{i}"),
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    };
                    self.builder
                        .build_store(byte_ptr, byte)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                }
            }
        }

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }
    /// Determine if a TypeInfo qualifies as a "simple variable" for PrintVariableIndex
    /// Simple: base types (bool/int/float/char), enums (with base type 1/2/4/8), pointers;
    /// Complex: arrays, structs, unions, functions
    fn is_simple_typeinfo(t: &ghostscope_dwarf::TypeInfo) -> bool {
        use ghostscope_dwarf::TypeInfo as TI;
        match t {
            TI::BaseType { size, .. } => matches!(*size, 1 | 2 | 4 | 8),
            TI::EnumType { base_type, .. } => {
                let sz = base_type.size();
                matches!(sz, 1 | 2 | 4 | 8)
            }
            TI::PointerType { .. } => true,
            TI::TypedefType {
                underlying_type, ..
            }
            | TI::QualifiedType {
                underlying_type, ..
            } => Self::is_simple_typeinfo(underlying_type),
            _ => false,
        }
    }

    /// Compute read size for a given DWARF type.
    /// No fallback: if DWARF doesn't provide size for arrays, return 0 and let caller error out.
    fn compute_read_size_for_type(t: &ghostscope_dwarf::TypeInfo) -> usize {
        use ghostscope_dwarf::TypeInfo as TI;
        match t {
            TI::ArrayType {
                element_type,
                element_count,
                total_size,
            } => {
                // Prefer DWARF-provided total size
                if let Some(ts) = total_size {
                    return *ts as usize;
                }
                // Fallback for arrays without total_size: need element_count * elem_size
                let elem_size = element_type.size() as usize;
                if elem_size == 0 {
                    return 0;
                }
                if let Some(cnt) = element_count {
                    return elem_size * (*cnt as usize);
                }
                0
            }
            TI::TypedefType {
                underlying_type, ..
            }
            | TI::QualifiedType {
                underlying_type, ..
            } => Self::compute_read_size_for_type(underlying_type),
            _ => t.size() as usize,
        }
    }

    // (No implicit char[] fallback here; rely on DWARF/type resolver to provide sizes.)

    fn expr_to_name(&self, expr: &crate::script::ast::Expr) -> String {
        use crate::script::ast::Expr as E;
        fn inner(e: &E) -> String {
            match e {
                E::Variable(s) => s.clone(),
                E::MemberAccess(obj, field) => format!("{}.{field}", inner(obj)),
                E::ArrayAccess(arr, idx) => format!("{}[{}]", inner(arr), inner(idx)),
                E::PointerDeref(p) => format!("*{}", inner(p)),
                E::AddressOf(p) => format!("&{}", inner(p)),
                E::ChainAccess(v) => v.join("."),
                E::Int(v) => v.to_string(),
                E::String(s) => format!("\"{s}\""),
                E::Float(v) => format!("{v}"),
                E::UnaryNot(e1) => format!("!{}", inner(e1)),
                E::Bool(v) => v.to_string(),
                E::SpecialVar(s) => format!("${s}"),
                E::BuiltinCall { name, args } => {
                    let arg_strs: Vec<String> = args.iter().map(inner).collect();
                    format!("{}({})", name, arg_strs.join(", "))
                }
                E::BinaryOp { left, op, right } => {
                    let op_str = match op {
                        crate::script::ast::BinaryOp::Add => "+",
                        crate::script::ast::BinaryOp::Subtract => "-",
                        crate::script::ast::BinaryOp::Multiply => "*",
                        crate::script::ast::BinaryOp::Divide => "/",
                        crate::script::ast::BinaryOp::Equal => "==",
                        crate::script::ast::BinaryOp::NotEqual => "!=",
                        crate::script::ast::BinaryOp::LessThan => "<",
                        crate::script::ast::BinaryOp::LessEqual => "<=",
                        crate::script::ast::BinaryOp::GreaterThan => ">",
                        crate::script::ast::BinaryOp::GreaterEqual => ">=",
                        crate::script::ast::BinaryOp::LogicalAnd => "&&",
                        crate::script::ast::BinaryOp::LogicalOr => "||",
                    };
                    format!("({}{}{})", inner(left), op_str, inner(right))
                }
            }
        }
        let s_full = inner(expr);
        const MAX_NAME: usize = 96;
        if s_full.chars().count() > MAX_NAME {
            // Keep space for ellipsis
            let keep = MAX_NAME.saturating_sub(3);
            let mut acc = String::with_capacity(MAX_NAME);
            for (i, ch) in s_full.chars().enumerate() {
                if i >= keep {
                    break;
                }
                acc.push(ch);
            }
            acc.push_str("...");
            acc
        } else {
            s_full
        }
    }

    /// Heuristic to decide if an expression should be bound as a DWARF alias variable.
    /// Prefer shapes that resolve to a runtime address via DWARF or address-of:
    /// - AddressOf(...)
    /// - Member/Array/PointerDeref/Chain access
    /// - Variable that is a DWARF-backed symbol (not a script var)
    /// - Simple constant-offset on top of an aliasy expression: alias + K (K >= 0)
    fn is_alias_candidate_expr(&mut self, expr: &crate::script::ast::Expr) -> bool {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;
        match expr {
            // Alias variable names are alias candidates
            E::Variable(name) if self.alias_variable_exists(name) => true,
            // Explicit address-of is always an alias
            E::AddressOf(_) => true,
            // Constant offset on top of an alias-eligible expression
            E::BinaryOp {
                left,
                op: BO::Add,
                right,
            } => {
                let is_const_nonneg = |e: &E| matches!(e, E::Int(v) if *v >= 0);
                (self.is_alias_candidate_expr(left) && is_const_nonneg(right))
                    || (self.is_alias_candidate_expr(right) && is_const_nonneg(left))
            }
            // Otherwise, probe DWARF type: any DWARF-backed expression (pointer/array/struct/union/enum)
            // is treated as an alias so it can be used as a reusable base for member/index/address-of.
            other => matches!(self.query_dwarf_for_complex_expr(other), Ok(Some(_))),
        }
    }

    // removed old helpers (pure lvalue/binary_op detection) — unified resolver handles shapes

    /// Main entry point: compile program with staged transmission system
    pub fn compile_program_with_staged_transmission(
        &mut self,
        program: &Program,
        _variable_types: HashMap<String, TypeKind>,
    ) -> Result<TraceContext> {
        info!("Compiling program with staged transmission system");

        // Step 1: Send TraceEventHeader
        self.send_trace_event_header()?;
        info!("Sent TraceEventHeader");

        // Step 2: Send TraceEventMessage with dynamic trace_id
        let trace_id = self.current_trace_id.map(|id| id as u64).unwrap_or(0);
        self.send_trace_event_message(trace_id)?;
        info!("Sent TraceEventMessage");

        // Reset per-event execution status flags
        self.store_flag_value("_gs_any_fail", 0)?;
        self.store_flag_value("_gs_any_success", 0)?;

        // Step 3: Process each statement and generate LLVM IR on-demand
        let mut instruction_count = 0u16;
        for statement in &program.statements {
            instruction_count += self.compile_statement(statement)?;
        }

        // Step 4: Send EndInstruction to mark completion
        self.send_end_instruction(instruction_count)?;
        info!(
            "Sent EndInstruction with {} total instructions",
            instruction_count
        );

        // Step 5: Return the trace context for user-space parsing
        Ok(self.trace_context.clone())
    }

    /// Compile a statement and return the number of instructions generated
    pub fn compile_statement(&mut self, statement: &Statement) -> Result<u16> {
        debug!("Compiling statement: {:?}", statement);

        match statement {
            Statement::AliasDeclaration { name, target } => {
                info!("Registering alias variable: {} = {:?}", name, target);
                // Declare in current scope (no redeclaration or shadowing)
                self.declare_name_in_current_scope(name)?;
                self.set_alias_variable(name, target.clone());
                Ok(0)
            }
            Statement::VarDeclaration { name, value } => {
                info!("Processing variable declaration: {} = {:?}", name, value);
                // Declare in current scope (no redeclaration or shadowing)
                self.declare_name_in_current_scope(name)?;
                // Decide whether this is an alias binding (DWARF-backed address/reference)
                if self.is_alias_candidate_expr(value) {
                    self.set_alias_variable(name, value.clone());
                    tracing::debug!(var=%name, "Registered DWARF alias variable");
                    Ok(0)
                } else {
                    // Compile the value expression and store as concrete variable
                    // Special-case: string literal and string var copy — record bytes for content printing
                    match value {
                        crate::script::Expr::String(s) => {
                            let mut bytes = s.as_bytes().to_vec();
                            bytes.push(0); // NUL terminate for display convenience
                            self.set_string_variable_bytes(name, bytes);
                        }
                        crate::script::Expr::Variable(ref nm) => {
                            if self
                                .get_variable_type(nm)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String))
                            {
                                if let Some(b) = self.get_string_variable_bytes(nm).cloned() {
                                    self.set_string_variable_bytes(name, b);
                                }
                            }
                        }
                        _ => {}
                    }
                    let compiled_value = self.compile_expr(value)?;
                    // Disallow storing pointer values in script variables, except for string literals
                    if let BasicValueEnum::PointerValue(_) = compiled_value {
                        // Allow if RHS is a string literal OR a string variable (VarType::String)
                        let allow_string_var_copy = match value {
                            crate::script::Expr::String(_) => true,
                            crate::script::Expr::Variable(ref nm) => self
                                .get_variable_type(nm)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String)),
                            _ => false,
                        };
                        if !allow_string_var_copy {
                            return Err(CodeGenError::TypeError(
                                "script variables cannot store pointer values; use DWARF alias (let v = &expr) or keep it as a string".to_string(),
                            ));
                        }
                    }
                    self.store_variable(name, compiled_value)?;
                    Ok(0) // VarDeclaration doesn't generate instructions
                }
            }
            Statement::Print(print_stmt) => self.compile_print_statement(print_stmt),
            Statement::If {
                condition,
                then_body,
                else_body,
            } => {
                // Prepare condition context (runtime error capture)
                // Pretty expression text for warning
                let expr_text = self.expr_to_name(condition);
                let expr_index = self.trace_context.add_string(expr_text);
                // Activate condition context (compile-time flag) and reset runtime error byte
                self.condition_context_active = true;
                self.reset_condition_error()?;

                // Compile condition expression
                let cond_value = self.compile_expr(condition)?;

                // Convert condition to i1 (boolean) for branching
                let cond_bool = match cond_value {
                    BasicValueEnum::IntValue(int_val) => {
                        // Convert integer to boolean (non-zero = true)
                        self.builder
                            .build_int_compare(
                                inkwell::IntPredicate::NE,
                                int_val,
                                int_val.get_type().const_zero(),
                                "cond_bool",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to create condition: {e}"))
                            })?
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Condition must evaluate to integer".to_string(),
                        ));
                    }
                };

                // Get current function from builder
                let current_function = self
                    .builder
                    .get_insert_block()
                    .ok_or_else(|| CodeGenError::LLVMError("No current basic block".to_string()))?
                    .get_parent()
                    .ok_or_else(|| CodeGenError::LLVMError("No parent function".to_string()))?;

                // Create basic blocks for error/noerror and then/else paths
                let then_block = self
                    .context
                    .append_basic_block(current_function, "then_block");
                let else_block = self
                    .context
                    .append_basic_block(current_function, "else_block");
                let merge_block = self
                    .context
                    .append_basic_block(current_function, "merge_block");
                let err_block = self
                    .context
                    .append_basic_block(current_function, "cond_err_block");
                let ok_block = self
                    .context
                    .append_basic_block(current_function, "cond_ok_block");
                // After cond compiled, deactivate compile-time flag
                self.condition_context_active = false;

                // First branch: did runtime errors occur while evaluating the condition?
                let cond_err_pred = self.build_condition_error_predicate()?;
                self.builder
                    .build_conditional_branch(cond_err_pred, err_block, ok_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch on cond_err: {e}"))
                    })?;

                // Error path: emit ExprError and decide destination
                self.builder.position_at_end(err_block);
                let cond_err_ptr = self.get_or_create_cond_error_global();
                let err_code = self
                    .builder
                    .build_load(self.context.i8_type(), cond_err_ptr, "cond_err_code")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    .into_int_value();
                // Also load failing address (i64)
                let cond_err_addr_ptr = self.get_or_create_cond_error_addr_global();
                let err_addr = self
                    .builder
                    .build_load(self.context.i64_type(), cond_err_addr_ptr, "cond_err_addr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    .into_int_value();
                // Load flags
                let cond_err_flags_ptr = self.get_or_create_cond_error_flags_global();
                let err_flags = self
                    .builder
                    .build_load(self.context.i8_type(), cond_err_flags_ptr, "cond_err_flags")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    .into_int_value();
                self.generate_expr_error(expr_index, err_code, err_flags, err_addr)?;
                // Decide where to go on error: if else_body is If (else-if), go to else_block to continue;
                // otherwise, skip else (suppress) and jump to merge.
                let goto_else = matches!(else_body.as_deref(), Some(Statement::If { .. }));
                if goto_else {
                    self.builder
                        .build_unconditional_branch(else_block)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!(
                                "Failed to branch to else on error: {e}"
                            ))
                        })?;
                } else {
                    self.builder
                        .build_unconditional_branch(merge_block)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!(
                                "Failed to branch to merge on error: {e}"
                            ))
                        })?;
                }

                // No-error path: branch on boolean condition
                self.builder.position_at_end(ok_block);
                self.builder
                    .build_conditional_branch(cond_bool, then_block, else_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to create branch: {e}"))
                    })?;

                // Build then block
                self.builder.position_at_end(then_block);
                let mut then_instructions = 0u16;
                self.enter_scope();
                for stmt in then_body {
                    then_instructions += self.compile_statement(stmt)?;
                }
                self.exit_scope();
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {e}"))
                    })?;

                // Build else block
                self.builder.position_at_end(else_block);
                let mut else_instructions = 0u16;
                if let Some(else_stmt) = else_body {
                    self.enter_scope();
                    else_instructions += self.compile_statement(else_stmt)?;
                    self.exit_scope();
                }
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {e}"))
                    })?;

                // Continue with merge block
                self.builder.position_at_end(merge_block);

                // Return the maximum instructions from either branch
                Ok(std::cmp::max(then_instructions, else_instructions))
            }
            Statement::Block(nested_statements) => {
                let mut total_instructions = 0u16;
                self.enter_scope();
                for stmt in nested_statements {
                    total_instructions += self.compile_statement(stmt)?;
                }
                self.exit_scope();
                Ok(total_instructions)
            }
            Statement::TracePoint { pattern: _, body } => {
                let mut total_instructions = 0u16;
                // Start a new scope for the trace body
                self.enter_scope();
                for stmt in body {
                    total_instructions += self.compile_statement(stmt)?;
                }
                self.exit_scope();
                Ok(total_instructions)
            }
            _ => {
                warn!("Unsupported statement type: {:?}", statement);
                Ok(0)
            }
        }
    }

    /// Compile print statement and generate LLVM IR on-demand
    pub fn compile_print_statement(&mut self, print_stmt: &PrintStatement) -> Result<u16> {
        info!("Compiling print statement: {:?}", print_stmt);

        match print_stmt {
            PrintStatement::String(s) => {
                info!("Processing string literal: {}", s);
                // 1. Add string to TraceContext
                let string_index = self.trace_context.add_string(s.to_string());
                // 2. Generate eBPF code for PrintStringIndex
                self.generate_print_string_index(string_index)?;
                Ok(1) // Generated 1 instruction
            }
            PrintStatement::Variable(var_name) => {
                info!("Processing variable: {}", var_name);
                let expr = crate::script::Expr::Variable(var_name.clone());
                let arg = self.resolve_expr_to_arg(&expr)?;
                let n = self.emit_print_from_arg(arg)?;
                tracing::trace!(
                    var_name = %var_name,
                    instructions = n,
                    "compile_print_statement: emitted via unified resolver"
                );
                Ok(n)
            }
            PrintStatement::ComplexVariable(expr) => {
                info!("Processing complex variable: {:?}", expr);
                let arg = self.resolve_expr_to_arg(expr)?;
                let n = self.emit_print_from_arg(arg)?;
                tracing::trace!(
                    instructions = n,
                    "compile_print_statement: emitted via unified resolver"
                );
                Ok(n)
            }
            PrintStatement::Formatted { format, args } => {
                info!(
                    "Processing formatted print: '{}' with {} args",
                    format,
                    args.len()
                );
                self.compile_formatted_print(format, args)
            }
        }
    }

    /// Compile formatted print statement: collect all variable data and send as PrintComplexFormat instruction
    fn compile_formatted_print(
        &mut self,
        format: &str,
        args: &[crate::script::ast::Expr],
    ) -> Result<u16> {
        info!(
            "Compiling formatted print: '{}' with {} arguments",
            format,
            args.len()
        );
        let format_string_index = self.trace_context.add_string(format.to_string());
        let mut complex_args: Vec<ComplexArg<'ctx>> = Vec::with_capacity(args.len());

        // Parse placeholders from the format string to support extended specifiers
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Conv {
            Default,
            HexLower,
            HexUpper,
            Ptr,
            Ascii,
        }
        #[derive(Clone, Debug, PartialEq)]
        enum LenSpec {
            None,
            Static(usize),
            Star,
            Capture(String),
        }

        fn parse_slots(fmt: &str) -> Vec<(Conv, LenSpec)> {
            let mut res = Vec::new();
            let mut it = fmt.chars().peekable();
            while let Some(ch) = it.next() {
                if ch == '{' {
                    if it.peek() == Some(&'{') {
                        it.next();
                        continue;
                    }
                    let mut content = String::new();
                    for c in it.by_ref() {
                        if c == '}' {
                            break;
                        }
                        content.push(c);
                    }
                    if content.is_empty() {
                        res.push((Conv::Default, LenSpec::None));
                    } else if let Some(rest) = content.strip_prefix(':') {
                        let mut sit = rest.chars();
                        let conv = match sit.next().unwrap_or(' ') {
                            'x' => Conv::HexLower,
                            'X' => Conv::HexUpper,
                            'p' => Conv::Ptr,
                            's' => Conv::Ascii,
                            _ => Conv::Default,
                        };
                        let rest: String = sit.collect();
                        let lens = if rest.is_empty() {
                            LenSpec::None
                        } else if let Some(r) = rest.strip_prefix('.') {
                            if r == "*" {
                                LenSpec::Star
                            } else if let Some(s) = r.strip_suffix('$') {
                                LenSpec::Capture(s.to_string())
                            } else if r.chars().all(|c| c.is_ascii_digit()) {
                                LenSpec::Static(r.parse::<usize>().unwrap_or(0))
                            } else {
                                LenSpec::None
                            }
                        } else {
                            LenSpec::None
                        };
                        res.push((conv, lens));
                    } else {
                        res.push((Conv::Default, LenSpec::None));
                    }
                }
            }
            res
        }

        let slots = parse_slots(format);
        let mut ai = 0usize; // arg cursor
        for (conv, lens) in slots.into_iter() {
            match conv {
                Conv::Default => {
                    if ai >= args.len() {
                        break;
                    }
                    let a = self.resolve_expr_to_arg(&args[ai])?;
                    complex_args.push(a);
                    ai += 1;
                }
                Conv::Ptr => {
                    if ai >= args.len() {
                        break;
                    }
                    // Force pointer address payload (u64) regardless of DWARF shape
                    let expr = &args[ai];
                    // Try compile to IntValue or PointerValue
                    let val = self.compile_expr(expr)?;
                    let iv = match val {
                        BasicValueEnum::IntValue(iv) => iv,
                        BasicValueEnum::PointerValue(pv) => self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                        _ => self
                            .compile_dwarf_expression(expr)
                            .and_then(|bv| match bv {
                                BasicValueEnum::IntValue(iv) => Ok(iv),
                                BasicValueEnum::PointerValue(pv) => self
                                    .builder
                                    .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                                    .map_err(|e| CodeGenError::Builder(e.to_string())),
                                _ => Err(CodeGenError::TypeError("pointer expected".into())),
                            })?,
                    };
                    complex_args.push(ComplexArg {
                        var_name_index: self
                            .trace_context
                            .add_variable_name(self.expr_to_name(expr)),
                        type_index: self.add_synthesized_type_index_for_kind(TypeKind::Pointer),
                        access_path: Vec::new(),
                        data_len: 8,
                        source: ComplexArgSource::ComputedInt {
                            value: iv,
                            byte_len: 8,
                        },
                    });
                    ai += 1;
                }
                Conv::HexLower | Conv::HexUpper | Conv::Ascii => {
                    // Memory dump; handle static length at compile time. Other cases use default read and let user space trim.
                    // Handle star: consume length arg (as computed int) then value arg
                    let wants_ascii = matches!(conv, Conv::Ascii);
                    match lens {
                        LenSpec::Static(n) if ai < args.len() => {
                            // Resolve value expr address
                            let expr = &args[ai];
                            // Try get pointer address directly from expr value
                            let val = self.compile_expr(expr).ok();
                            let mut addr_iv: Option<IntValue> = match val {
                                Some(BasicValueEnum::PointerValue(pv)) => Some(
                                    self.builder
                                        .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                                ),
                                _ => None,
                            };
                            // If compiled value is IntValue but DWARF type is a pointer, treat the IntValue as an address (pointer value)
                            if addr_iv.is_none() {
                                if let Some(BasicValueEnum::IntValue(iv)) = val {
                                    if let Some(var) = self.query_dwarf_for_complex_expr(expr)? {
                                        if let Some(ref t) = var.dwarf_type {
                                            if matches!(
                                                t,
                                                ghostscope_dwarf::TypeInfo::PointerType { .. }
                                            ) {
                                                addr_iv = Some(iv);
                                            }
                                        }
                                    }
                                }
                            }
                            let addr_iv = if let Some(iv) = addr_iv {
                                iv
                            } else {
                                // Fallback: DWARF address (for arrays/char[N])
                                let var =
                                    self.query_dwarf_for_complex_expr(expr)?.ok_or_else(|| {
                                        CodeGenError::VariableNotFound(format!("{expr:?}"))
                                    })?;
                                let mod_hint = self.take_module_hint();
                                self.evaluation_result_to_address_with_hint(
                                    &var.evaluation_result,
                                    None,
                                    mod_hint.as_deref(),
                                )?
                            };
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(expr)),
                                type_index: self
                                    .trace_context
                                    .add_type(ghostscope_dwarf::TypeInfo::ArrayType {
                                    element_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                                        name: "u8".into(),
                                        size: 1,
                                        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char
                                            .0
                                            as u16,
                                    }),
                                    element_count: Some(n as u64),
                                    total_size: Some(n as u64),
                                }),
                                access_path: Vec::new(),
                                data_len: n,
                                source: ComplexArgSource::MemDump {
                                    src_addr: addr_iv,
                                    len: n,
                                },
                            });
                            ai += 1;
                        }
                        LenSpec::Star => {
                            // Dynamic length: consume length arg, then create a dynamic mem-dump for value
                            if ai + 1 >= args.len() {
                                break;
                            }
                            // length argument
                            let len_expr = &args[ai];
                            let len_val = self.compile_expr(len_expr)?;
                            let (len_iv, byte_len) = match len_val {
                                BasicValueEnum::IntValue(iv) => (iv, 8usize),
                                _ => {
                                    return Err(CodeGenError::TypeError(
                                        "length must be integer".into(),
                                    ))
                                }
                            };
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name("__len".into()),
                                type_index: self.add_synthesized_type_index_for_kind(TypeKind::U64),
                                access_path: Vec::new(),
                                data_len: byte_len,
                                source: ComplexArgSource::ComputedInt {
                                    value: len_iv,
                                    byte_len,
                                },
                            });

                            // value expression -> dynamic memdump with cap
                            let val_expr = &args[ai + 1];
                            // Resolve base address either from pointer-typed value or DWARF evaluation
                            let val = self.compile_expr(val_expr).ok();
                            let mut addr_iv: Option<IntValue> = match val {
                                Some(BasicValueEnum::PointerValue(pv)) => Some(
                                    self.builder
                                        .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                                ),
                                _ => None,
                            };
                            if addr_iv.is_none() {
                                if let Some(BasicValueEnum::IntValue(iv)) = val {
                                    if let Some(var) =
                                        self.query_dwarf_for_complex_expr(val_expr)?
                                    {
                                        if let Some(ref t) = var.dwarf_type {
                                            if matches!(
                                                t,
                                                ghostscope_dwarf::TypeInfo::PointerType { .. }
                                            ) {
                                                addr_iv = Some(iv);
                                            }
                                        }
                                    }
                                }
                            }
                            let addr_iv = if let Some(iv) = addr_iv {
                                iv
                            } else {
                                let var = self.query_dwarf_for_complex_expr(val_expr)?.ok_or_else(
                                    || CodeGenError::VariableNotFound(format!("{val_expr:?}")),
                                )?;
                                let mod_hint = self.take_module_hint();
                                self.evaluation_result_to_address_with_hint(
                                    &var.evaluation_result,
                                    None,
                                    mod_hint.as_deref(),
                                )?
                            };
                            // Reserve up to configured per-arg cap for dynamic slices
                            let cap = self.compile_options.mem_dump_cap as usize;
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(val_expr)),
                                type_index: self
                                    .trace_context
                                    .add_type(ghostscope_dwarf::TypeInfo::ArrayType {
                                    element_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                                        name: "u8".into(),
                                        size: 1,
                                        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char
                                            .0
                                            as u16,
                                    }),
                                    element_count: Some(cap as u64),
                                    total_size: Some(cap as u64),
                                }),
                                access_path: Vec::new(),
                                data_len: cap,
                                source: ComplexArgSource::MemDumpDynamic {
                                    src_addr: addr_iv,
                                    len_value: len_iv,
                                    max_len: cap,
                                },
                            });
                            ai += 2;
                        }
                        LenSpec::Capture(name) => {
                            // Use script variable `name` as length; emit a length argument + a dynamic mem-dump argument
                            if ai >= args.len() {
                                break;
                            }
                            if !self.variable_exists(&name) {
                                return Err(CodeGenError::TypeError(format!(
                                    "capture length variable '{name}' not found"
                                )));
                            }
                            // length as computed int
                            let len_val = self.load_variable(&name)?;
                            let (len_iv, byte_len) = match len_val {
                                BasicValueEnum::IntValue(iv) => (iv, 8usize),
                                BasicValueEnum::PointerValue(pv) => (
                                    self.builder
                                        .build_ptr_to_int(
                                            pv,
                                            self.context.i64_type(),
                                            "len_ptr_to_i64",
                                        )
                                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                                    8usize,
                                ),
                                _ => {
                                    return Err(CodeGenError::TypeError(
                                        "length must be integer/pointer".into(),
                                    ))
                                }
                            };
                            complex_args.push(ComplexArg {
                                var_name_index: self.trace_context.add_variable_name(name.clone()),
                                type_index: self.add_synthesized_type_index_for_kind(TypeKind::U64),
                                access_path: Vec::new(),
                                data_len: byte_len,
                                source: ComplexArgSource::ComputedInt {
                                    value: len_iv,
                                    byte_len,
                                },
                            });

                            // value
                            let val_expr = &args[ai];
                            let val = self.compile_expr(val_expr).ok();
                            let mut addr_iv: Option<IntValue> = match val {
                                Some(BasicValueEnum::PointerValue(pv)) => Some(
                                    self.builder
                                        .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                                ),
                                _ => None,
                            };
                            if addr_iv.is_none() {
                                if let Some(BasicValueEnum::IntValue(iv)) = val {
                                    if let Some(var) =
                                        self.query_dwarf_for_complex_expr(val_expr)?
                                    {
                                        if let Some(ref t) = var.dwarf_type {
                                            if matches!(
                                                t,
                                                ghostscope_dwarf::TypeInfo::PointerType { .. }
                                            ) {
                                                addr_iv = Some(iv);
                                            }
                                        }
                                    }
                                }
                            }
                            let addr_iv = if let Some(iv) = addr_iv {
                                iv
                            } else {
                                let var = self.query_dwarf_for_complex_expr(val_expr)?.ok_or_else(
                                    || CodeGenError::VariableNotFound(format!("{val_expr:?}")),
                                )?;
                                let mod_hint = self.take_module_hint();
                                self.evaluation_result_to_address_with_hint(
                                    &var.evaluation_result,
                                    None,
                                    mod_hint.as_deref(),
                                )?
                            };
                            let cap = self.compile_options.mem_dump_cap as usize;
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(val_expr)),
                                type_index: self
                                    .trace_context
                                    .add_type(ghostscope_dwarf::TypeInfo::ArrayType {
                                    element_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                                        name: "u8".into(),
                                        size: 1,
                                        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char
                                            .0
                                            as u16,
                                    }),
                                    element_count: Some(cap as u64),
                                    total_size: Some(cap as u64),
                                }),
                                access_path: Vec::new(),
                                data_len: cap,
                                source: ComplexArgSource::MemDumpDynamic {
                                    src_addr: addr_iv,
                                    len_value: len_iv,
                                    max_len: cap,
                                },
                            });
                            ai += 1;
                        }
                        _ => {
                            // None: resolve value directly
                            if ai >= args.len() {
                                break;
                            }
                            complex_args.push(self.resolve_expr_to_arg(&args[ai])?);
                            ai += 1;
                        }
                    }
                    let _ = wants_ascii; // reserved for future per-arg metadata
                }
            }
        }
        self.generate_print_complex_format_instruction(format_string_index, &complex_args)?;
        Ok(1)
    }

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
            let var_name_index = self.trace_context.add_variable_name(var_name.to_string());

            return Ok((var_name_index, type_encoding));
        }

        // Step 2: If not found in script variables, try DWARF variables
        info!(
            "Variable '{}' not found in script variables, checking DWARF",
            var_name
        );

        let compile_context = self.get_compile_time_context()?.clone();
        let variable_with_eval = match self.query_dwarf_for_variable(var_name)? {
            Some(var) => var,
            None => {
                return Err(CodeGenError::VariableNotFound(format!(
                    "Variable '{}' not found in script or DWARF at PC 0x{:x} in module '{}'",
                    var_name, compile_context.pc_address, compile_context.module_path
                )));
            }
        };

        // Convert DWARF type information to TypeKind using existing method
        let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Variable has no DWARF type information".to_string())
        })?;
        let type_encoding = TypeKind::from(dwarf_type);

        // Add to StringTable
        let var_name_index = self.trace_context.add_variable_name(var_name.to_string());

        info!(
            "DWARF variable '{}' resolved successfully with type: {:?}",
            var_name, type_encoding
        );

        Ok((var_name_index, type_encoding))
    }

    /// Synthesize a DWARF-like TypeInfo for a basic TypeKind (for script variables)
    fn synthesize_typeinfo_for_typekind(&self, kind: TypeKind) -> ghostscope_dwarf::TypeInfo {
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

    fn add_synthesized_type_index_for_kind(&mut self, kind: TypeKind) -> u16 {
        let ti = self.synthesize_typeinfo_for_typekind(kind);
        self.trace_context.add_type(ti)
    }

    /// Infer TypeKind from LLVM value type
    /// Copied from protocol.rs
    fn infer_type_from_llvm_value(&self, value: &BasicValueEnum<'_>) -> TypeKind {
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

    /// Generate eBPF code for PrintComplexFormat instruction with runtime reads for variables
    fn generate_print_complex_format_instruction(
        &mut self,
        format_string_index: u16,
        complex_args: &[ComplexArg<'ctx>],
    ) -> Result<()> {
        use ghostscope_protocol::trace_event::PrintComplexFormatData;
        use InstructionType::PrintComplexFormat as IT;

        // Calculate total size with buffer-capacity awareness to avoid overflow
        // Instruction buffer capacity is currently 4096 (see create_instruction_buffer)
        const INSTR_BUF_CAP: usize = 4096;
        let fixed_overhead = std::mem::size_of::<InstructionHeader>()
            + std::mem::size_of::<PrintComplexFormatData>();

        // First pass: accumulate header bytes and static payload, record dynamic args
        let mut arg_count = 0u8;
        let mut headers_total = 0usize;
        let mut static_payload_total = 0usize;
        let mut dynamic_indices: Vec<(usize, usize)> = Vec::new(); // (arg_idx, max_len)
        let mut header_lens: Vec<usize> = Vec::with_capacity(complex_args.len());
        for (idx, a) in complex_args.iter().enumerate() {
            // Header bytes per-arg: var_name_index(2) + type_index(2) + access_path_len(1) + status(1) + data_len(2) + access_path
            let header_len = 2 + 2 + 1 + 1 + 2 + a.access_path.len();
            header_lens.push(header_len);
            headers_total += header_len;

            match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => static_payload_total += bytes.len(),
                ComplexArgSource::AddressValue { .. } => static_payload_total += 8,
                ComplexArgSource::RuntimeRead { .. } => {
                    static_payload_total += std::cmp::max(a.data_len, 12)
                }
                ComplexArgSource::ComputedInt { byte_len, .. } => static_payload_total += *byte_len,
                ComplexArgSource::MemDump { len, .. } => {
                    static_payload_total += std::cmp::max(*len, 12)
                }
                ComplexArgSource::MemDumpDynamic { max_len, .. } => {
                    dynamic_indices.push((idx, *max_len))
                }
            }
            arg_count = arg_count.saturating_add(1);
        }

        // Available space for all argument payloads within the instruction buffer
        // Ensure we never exceed INSTR_BUF_CAP
        let mut remaining_for_payload = INSTR_BUF_CAP
            .saturating_sub(fixed_overhead)
            .saturating_sub(headers_total);

        // Allocate static payload first
        remaining_for_payload = remaining_for_payload.saturating_sub(static_payload_total);

        // Second pass: decide effective reserved payload for each arg
        // Default to computed static payload; dynamic args get clamped to remaining space
        let mut effective_reserved: Vec<usize> = Vec::with_capacity(complex_args.len());
        for (idx, a) in complex_args.iter().enumerate() {
            let reserved = match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => bytes.len(),
                ComplexArgSource::AddressValue { .. } => 8,
                ComplexArgSource::RuntimeRead { .. } => std::cmp::max(a.data_len, 12),
                ComplexArgSource::ComputedInt { byte_len, .. } => *byte_len,
                ComplexArgSource::MemDump { len, .. } => std::cmp::max(*len, 12),
                ComplexArgSource::MemDumpDynamic { .. } => {
                    // find max_len for this dynamic arg and clamp to remaining
                    let (_, max_len) = dynamic_indices
                        .iter()
                        .copied()
                        .find(|(i, _)| *i == idx)
                        .unwrap_or((idx, 0));
                    // Ensure we always have space for error payload (errno+addr = 12 bytes) if possible
                    let need = std::cmp::max(12usize, max_len);
                    let eff = std::cmp::min(need, remaining_for_payload);
                    remaining_for_payload = remaining_for_payload.saturating_sub(eff);
                    eff
                }
            };
            effective_reserved.push(reserved);
        }

        // Now compute final inst_data_size using effective reservations
        let total_args_payload: usize =
            header_lens.iter().sum::<usize>() + effective_reserved.iter().sum::<usize>();
        let inst_data_size = std::mem::size_of::<PrintComplexFormatData>() + total_args_payload;
        let total_size = std::mem::size_of::<InstructionHeader>() + inst_data_size;

        // Reserve buffer directly in accumulation buffer to avoid extra copy
        let buffer = self.reserve_instruction_region(total_size as u64);

        // Avoid memset; global buffer is zero-initialized

        // Write InstructionHeader
        let inst_type_val = self.context.i8_type().const_int(IT as u8 as u64, false);
        self.builder
            .build_store(buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;
        // data_length at +1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(inst_data_size as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Write PrintComplexFormatData at offset 4
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(4, false)],
                    "pcf_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get pcf_data_ptr GEP: {e}"))
                })?
        };

        // format_string_index (u16) at +0
        let fsi_ptr = self
            .builder
            .build_pointer_cast(
                data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "fsi_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast fsi_ptr: {e}")))?;
        let fsi_val = self
            .context
            .i16_type()
            .const_int(format_string_index as u64, false);
        self.builder
            .build_store(fsi_ptr, fsi_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store fsi: {e}")))?;
        // arg_count (u8) at +2
        let arg_cnt_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(2, false)],
                    "arg_count_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get arg_count GEP: {e}")))?
        };
        self.builder
            .build_store(
                arg_cnt_ptr,
                self.context.i8_type().const_int(arg_count as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store arg_count: {e}")))?;

        // Start of variable payload after PrintComplexFormatData — use computed effective reservations
        let mut offset = std::mem::size_of::<PrintComplexFormatData>();
        for (arg_index, a) in complex_args.iter().enumerate() {
            // Per-arg reserved payload length
            let reserved_len = effective_reserved[arg_index];

            // Base pointer = data_ptr + offset
            let arg_base = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        data_ptr,
                        &[self.context.i32_type().const_int(offset as u64, false)],
                        "arg_base",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get arg_base GEP: {e}"))
                    })?
            };

            // var_name_index(u16) at +0
            let vni_cast = self
                .builder
                .build_pointer_cast(
                    arg_base,
                    self.context.ptr_type(AddressSpace::default()),
                    "vni_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast vni ptr: {e}")))?;
            self.builder
                .build_store(
                    vni_cast,
                    self.context
                        .i16_type()
                        .const_int(a.var_name_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store vni: {e}")))?;

            // type_index(u16) at +2
            let ti_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(2, false)],
                        "ti_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get ti GEP: {e}")))?
            };
            let ti_cast = self
                .builder
                .build_pointer_cast(
                    ti_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "ti_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast ti ptr: {e}")))?;
            self.builder
                .build_store(
                    ti_cast,
                    self.context
                        .i16_type()
                        .const_int(a.type_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store ti: {e}")))?;

            // status(u8) at +5
            let apl_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(5, false)],
                        "status_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get status GEP: {e}"))
                    })?
            };
            self.builder
                .build_store(apl_ptr, self.context.i8_type().const_int(0, false))
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

            // access_path_len(u8) at +4
            let apl_ptr2 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(4, false)],
                        "apl_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get apl GEP: {e}")))?
            };
            self.builder
                .build_store(
                    apl_ptr2,
                    self.context
                        .i8_type()
                        .const_int(a.access_path.len() as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store apl: {e}")))?;

            // access_path bytes at +6..+6+len
            for (i, b) in a.access_path.iter().enumerate() {
                let byte_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            arg_base,
                            &[self.context.i32_type().const_int((6 + i) as u64, false)],
                            &format!("ap_byte_{i}"),
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get ap byte GEP: {e}"))
                        })?
                };
                self.builder
                    .build_store(byte_ptr, self.context.i8_type().const_int(*b as u64, false))
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store ap byte: {e}"))
                    })?;
            }

            // data_len(u16) at +6+path_len (store reserved_len to keep layout consistent)
            let dl_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self
                            .context
                            .i32_type()
                            .const_int((6 + a.access_path.len()) as u64, false)],
                        "dl_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get dl GEP: {e}")))?
            };
            let dl_cast = self
                .builder
                .build_pointer_cast(
                    dl_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "dl_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast dl ptr: {e}")))?;
            self.builder
                .build_store(
                    dl_cast,
                    self.context
                        .i16_type()
                        .const_int(reserved_len as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;

            // variable data starts at +8+path_len
            let var_data_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self
                            .context
                            .i32_type()
                            .const_int((8 + a.access_path.len()) as u64, false)],
                        "var_data_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get var_data GEP: {e}"))
                    })?
            };

            // No dynamic cursor; we keep a compile-time offset and use reserved_len for layout

            match &a.source {
                ComplexArgSource::ImmediateBytes { bytes, .. } => {
                    for (i, b) in bytes.iter().enumerate() {
                        let byte_ptr = unsafe {
                            self.builder
                                .build_gep(
                                    self.context.i8_type(),
                                    var_data_ptr,
                                    &[self.context.i32_type().const_int(i as u64, false)],
                                    &format!("var_byte_{i}"),
                                )
                                .map_err(|e| {
                                    CodeGenError::LLVMError(format!(
                                        "Failed to get var byte GEP: {e}"
                                    ))
                                })?
                        };
                        self.builder
                            .build_store(
                                byte_ptr,
                                self.context.i8_type().const_int(*b as u64, false),
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to store var byte: {e}"))
                            })?;
                    }
                    // data_len already set to reserved_len
                }
                ComplexArgSource::MemDump { src_addr, len } => {
                    // Directly probe-read into payload to avoid byte-wise copies
                    let ptr_ty = self.context.ptr_type(AddressSpace::default());
                    let i64_ty = self.context.i64_type();
                    let i32_ty = self.context.i32_type();

                    // Helper: long bpf_probe_read_user(void *dst, u32 size, const void *src)
                    let dst_ptr = self
                        .builder
                        .build_pointer_cast(var_data_ptr, ptr_ty, "md_dst_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let base_src_ptr = self
                        .builder
                        .build_int_to_ptr(*src_addr, ptr_ty, "md_src_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let offsets_found = self.load_offsets_found_flag()?;
                    let not_found = self
                        .builder
                        .build_not(offsets_found, "md_offsets_miss")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let null_ptr = ptr_ty.const_null();
                    let src_ptr = self
                        .builder
                        .build_select::<BasicValueEnum<'ctx>, _>(
                            offsets_found,
                            base_src_ptr.into(),
                            null_ptr.into(),
                            "md_src_or_null",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                        .into_pointer_value();
                    let len_const = i32_ty.const_int(*len as u64, false);
                    let zero_i32 = i32_ty.const_zero();
                    let effective_len = self
                        .builder
                        .build_select::<BasicValueEnum<'ctx>, _>(
                            offsets_found,
                            len_const.into(),
                            zero_i32.into(),
                            "md_len_or_zero",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                        .into_int_value();
                    let ret = self
                        .create_bpf_helper_call(
                            aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user
                                as u64,
                            &[dst_ptr.into(), effective_len.into(), src_ptr.into()],
                            i64_ty.into(),
                            "probe_read_user_memdump",
                        )?
                        .into_int_value();

                    // Branch on ret == 0 and offsets available
                    let ok_pred = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::EQ,
                            ret,
                            i64_ty.const_zero(),
                            "md_ok",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let ok = self
                        .builder
                        .build_and(ok_pred, offsets_found, "md_ok_with_offsets")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let curr = self.builder.get_insert_block().unwrap();
                    let func = curr.get_parent().unwrap();
                    let ok_b = self.context.append_basic_block(func, "md_ok");
                    let err_b = self.context.append_basic_block(func, "md_err");
                    let cont_b = self.context.append_basic_block(func, "md_cont");
                    self.builder
                        .build_conditional_branch(ok, ok_b, err_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // ok: nothing extra to do
                    self.builder.position_at_end(ok_b);
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // err: either offsets missing or helper failure
                    self.builder.position_at_end(err_b);
                    let offsets_err_b = self.context.append_basic_block(func, "md_offsets_err");
                    let helper_err_b = self.context.append_basic_block(func, "md_helper_err");
                    self.builder
                        .build_conditional_branch(not_found, offsets_err_b, helper_err_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(offsets_err_b);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::OffsetsUnavailable as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(helper_err_b);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ReadError as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // write errno + addr (12 bytes) to var_data_ptr; reserved sizing ensures this fits
                    let errno_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "errno_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_store(errno_ptr, ret)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let addr_ptr_i8 = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[self.context.i32_type().const_int(4, false)],
                                "addr_ptr_i8",
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    };
                    let addr_ptr = self
                        .builder
                        .build_pointer_cast(
                            addr_ptr_i8,
                            self.context.ptr_type(AddressSpace::default()),
                            "addr_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_store(addr_ptr, *src_addr)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(cont_b);
                }
                ComplexArgSource::MemDumpDynamic {
                    src_addr,
                    len_value,
                    max_len: _,
                } => {
                    // Clamp runtime read to effective reserved length for this arg
                    let eff_max_len = effective_reserved[arg_index] as u32;
                    // Read up to rlen=min(len_value, max_len) into helper buffer, then copy bytes into payload
                    let i32_ty = self.context.i32_type();
                    let rlen_i32 = if len_value.get_type().get_bit_width() > 32 {
                        self.builder
                            .build_int_truncate(*len_value, i32_ty, "mdd_len_trunc")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    } else if len_value.get_type().get_bit_width() < 32 {
                        self.builder
                            .build_int_z_extend(*len_value, i32_ty, "mdd_len_zext")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    } else {
                        *len_value
                    };
                    // clamp negative to 0
                    let zero_i32 = i32_ty.const_zero();
                    let is_neg = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::SLT,
                            rlen_i32,
                            zero_i32,
                            "mdd_len_neg",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let rlen_nn = self
                        .builder
                        .build_select(is_neg, zero_i32, rlen_i32, "mdd_len_nn")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                        .into_int_value();

                    // Bound length by the reserved space (already ensures >= 12B when possible)
                    let max_const = i32_ty.const_int(eff_max_len as u64, false);
                    let gt = self
                        .builder
                        .build_int_compare(inkwell::IntPredicate::UGT, rlen_nn, max_const, "mdd_gt")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let sel_len = self
                        .builder
                        .build_select(gt, max_const, rlen_nn, "mdd_rlen")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                        .into_int_value();

                    // If effective length is zero, mark status and skip read.
                    let curr = self.builder.get_insert_block().unwrap();
                    let func = curr.get_parent().unwrap();
                    let zero_b = self.context.append_basic_block(func, "mdd_len_zero");
                    let read_b = self.context.append_basic_block(func, "mdd_len_read");
                    let cont_b = self.context.append_basic_block(func, "mdd_cont");
                    let is_zero = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::EQ,
                            sel_len,
                            i32_ty.const_zero(),
                            "mdd_len_zero",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_conditional_branch(is_zero, zero_b, read_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Zero-length branch: set status=ZeroLength and continue.
                    self.builder.position_at_end(zero_b);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ZeroLength as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Non-zero path: perform probe_read_user directly into var_data_ptr
                    self.builder.position_at_end(read_b);
                    let dst_ptr = self
                        .builder
                        .build_bit_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "mdd_dst_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let ptr_ty = self.context.ptr_type(AddressSpace::default());
                    let base_src_ptr = self
                        .builder
                        .build_int_to_ptr(*src_addr, ptr_ty, "mdd_src_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let offsets_found = self.load_offsets_found_flag()?;
                    let not_found = self
                        .builder
                        .build_not(offsets_found, "mdd_dyn_offsets_miss")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let null_ptr = ptr_ty.const_null();
                    let src_ptr = self
                        .builder
                        .build_select::<BasicValueEnum<'ctx>, _>(
                            offsets_found,
                            base_src_ptr.into(),
                            null_ptr.into(),
                            "mdd_src_or_null",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                        .into_pointer_value();
                    let zero_i32 = self.context.i32_type().const_zero();
                    let effective_len = self
                        .builder
                        .build_select::<BasicValueEnum<'ctx>, _>(
                            offsets_found,
                            sel_len.into(),
                            zero_i32.into(),
                            "mdd_len_or_zero",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                        .into_int_value();
                    let ret = self
                        .create_bpf_helper_call(
                            BPF_FUNC_probe_read_user as u64,
                            &[dst_ptr, effective_len.into(), src_ptr.into()],
                            self.context.i64_type().into(),
                            "probe_read_user_dyn",
                        )?
                        .into_int_value();
                    let ok_pred = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::EQ,
                            ret,
                            self.context.i64_type().const_zero(),
                            "mdd_ok",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let ok = self
                        .builder
                        .build_and(ok_pred, offsets_found, "mdd_ok_with_offsets")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let ok_b = self.context.append_basic_block(func, "mdd_ok");
                    let err_b = self.context.append_basic_block(func, "mdd_err");
                    self.builder
                        .build_conditional_branch(ok, ok_b, err_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // ok: data already in var_data_ptr
                    self.builder.position_at_end(ok_b);
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // err: status+errno+addr (clamped by reserved sizing)
                    self.builder.position_at_end(err_b);
                    let offsets_err_b = self.context.append_basic_block(func, "mdd_offsets_err");
                    let helper_err_b = self.context.append_basic_block(func, "mdd_helper_err");
                    self.builder
                        .build_conditional_branch(not_found, offsets_err_b, helper_err_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(offsets_err_b);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::OffsetsUnavailable as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(helper_err_b);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ReadError as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let errno_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "mdd_errno_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_store(errno_ptr, ret)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let addr_ptr_i8 = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[self.context.i32_type().const_int(4, false)],
                                "mdd_addr_ptr_i8",
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    };
                    let addr_ptr = self
                        .builder
                        .build_pointer_cast(
                            addr_ptr_i8,
                            self.context.ptr_type(AddressSpace::default()),
                            "mdd_addr_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_store(addr_ptr, *src_addr)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(cont_b);
                }
                ComplexArgSource::ComputedInt { value, byte_len } => {
                    // Write computed integer into payload buffer based on requested byte_len
                    // Ensure the destination pointer element type matches the stored value type.
                    match *byte_len {
                        1 => {
                            let bitw = value.get_type().get_bit_width();
                            let v = if bitw == 1 {
                                // Bool: zero-extend to keep 0/1 in payload
                                self.builder
                                    .build_int_z_extend(
                                        *value,
                                        self.context.i8_type(),
                                        "expr_zext_bool_i8",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw < 8 {
                                self.builder
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i8_type(),
                                        "expr_sext_i8",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw > 8 {
                                // wider than i8 -> truncate
                                self.builder
                                    .build_int_truncate(
                                        *value,
                                        self.context.i8_type(),
                                        "expr_trunc_i8",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                // exactly i8
                                *value
                            };
                            // var_data_ptr is i8* already; store directly
                            self.builder
                                .build_store(var_data_ptr, v)
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        }
                        2 => {
                            let bitw = value.get_type().get_bit_width();
                            let v = if bitw < 16 {
                                self.builder
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i16_type(),
                                        "expr_sext_i16",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw > 16 {
                                self.builder
                                    .build_int_truncate(
                                        *value,
                                        self.context.i16_type(),
                                        "expr_trunc_i16",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                // equal width: i16
                                *value
                            };
                            let i16_ptr_ty = self.context.ptr_type(AddressSpace::default());
                            let cast_ptr = self
                                .builder
                                .build_pointer_cast(var_data_ptr, i16_ptr_ty, "expr_i16_ptr")
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            self.builder
                                .build_store(cast_ptr, v)
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        }
                        4 => {
                            let bitw = value.get_type().get_bit_width();
                            let v = if bitw < 32 {
                                self.builder
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i32_type(),
                                        "expr_sext_i32",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw > 32 {
                                self.builder
                                    .build_int_truncate(
                                        *value,
                                        self.context.i32_type(),
                                        "expr_trunc_i32",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                // equal width: i32
                                *value
                            };
                            let i32_ptr_ty = self.context.ptr_type(AddressSpace::default());
                            let cast_ptr = self
                                .builder
                                .build_pointer_cast(var_data_ptr, i32_ptr_ty, "expr_i32_ptr")
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            self.builder
                                .build_store(cast_ptr, v)
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        }
                        8 => {
                            let v64 = if value.get_type().get_bit_width() < 64 {
                                self.builder
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i64_type(),
                                        "expr_sext",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                *value
                            };
                            let i64_ptr_ty = self.context.ptr_type(AddressSpace::default());
                            let cast_ptr = self
                                .builder
                                .build_pointer_cast(var_data_ptr, i64_ptr_ty, "expr_i64_ptr")
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            self.builder
                                .build_store(cast_ptr, v64)
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        }
                        n => {
                            // Fallback: write the lowest n bytes little-endian
                            // Truncate/extend to 64-bit, then emit byte stores
                            let v64 = if value.get_type().get_bit_width() < 64 {
                                self.builder
                                    .build_int_z_extend(
                                        *value,
                                        self.context.i64_type(),
                                        "expr_zext_fallback",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                *value
                            };
                            for i in 0..n {
                                // Extract byte i
                                let shift =
                                    self.context.i64_type().const_int((i * 8) as u64, false);
                                let shifted = self
                                    .builder
                                    .build_right_shift(v64, shift, false, &format!("expr_shr_{i}"))
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                let byte = self
                                    .builder
                                    .build_int_truncate(
                                        shifted,
                                        self.context.i8_type(),
                                        &format!("expr_byte_{i}"),
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                let byte_ptr = unsafe {
                                    self.builder
                                        .build_gep(
                                            self.context.i8_type(),
                                            var_data_ptr,
                                            &[self.context.i32_type().const_int(i as u64, false)],
                                            &format!("expr_byte_ptr_{i}"),
                                        )
                                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                                };
                                self.builder
                                    .build_store(byte_ptr, byte)
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            }
                        }
                    }
                }
                ComplexArgSource::RuntimeRead {
                    eval_result,
                    dwarf_type,
                    module_for_offsets,
                } => {
                    // Read from user memory at runtime via BPF helper
                    let ptr_type = self.context.ptr_type(AddressSpace::default());
                    let i32_type = self.context.i32_type();
                    let i64_type = self.context.i64_type();
                    let dst_ptr = self
                        .builder
                        .build_bit_cast(var_data_ptr, ptr_type, "dst_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let size_val = i32_type.const_int(a.data_len as u64, false);
                    // Compute source address; if link-time address, apply ASLR offsets via map
                    let src_addr = self.evaluation_result_to_address_with_hint(
                        eval_result,
                        Some(apl_ptr),
                        module_for_offsets.as_deref(),
                    )?;
                    let offsets_found = self.load_offsets_found_flag()?;
                    let current_block = self.builder.get_insert_block().unwrap();
                    let current_fn = current_block.get_parent().unwrap();
                    let cont2_block = self.context.append_basic_block(current_fn, "after_read");
                    let skip_block = self.context.append_basic_block(current_fn, "offsets_skip");
                    let found_block = self.context.append_basic_block(current_fn, "offsets_found");
                    self.builder
                        .build_conditional_branch(offsets_found, found_block, skip_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Offsets missing: record failure and continue without helper access.
                    self.builder.position_at_end(skip_block);
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Offsets found: proceed with null check and helper call.
                    self.builder.position_at_end(found_block);
                    let src_ptr = self
                        .builder
                        .build_int_to_ptr(src_addr, ptr_type, "src_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // status_ptr was stored in apl_ptr earlier (we named it status_ptr)
                    // Build NULL check
                    let zero64 = i64_type.const_zero();
                    let is_null = self
                        .builder
                        .build_int_compare(inkwell::IntPredicate::EQ, src_addr, zero64, "is_null")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let null_block = self.context.append_basic_block(current_fn, "null_deref");
                    let read_block = self.context.append_basic_block(current_fn, "read_user");
                    self.builder
                        .build_conditional_branch(is_null, null_block, read_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // NULL path: status=1, keep reserved_len in header, no data write (buffer pre-zeroed)
                    self.builder.position_at_end(null_block);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::NullDeref as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Read path
                    self.builder.position_at_end(read_block);
                    let ret = self
                        .create_bpf_helper_call(
                            BPF_FUNC_probe_read_user as u64,
                            &[dst_ptr, size_val.into(), src_ptr.into()],
                            i32_type.into(),
                            "probe_read_user",
                        )?
                        .into_int_value();
                    let is_err = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::SLT,
                            ret,
                            i32_type.const_zero(),
                            "ret_lt_zero",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let err_block = self.context.append_basic_block(current_fn, "read_err");
                    let ok_block = self.context.append_basic_block(current_fn, "read_ok");
                    self.builder
                        .build_conditional_branch(is_err, err_block, ok_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Error branch: status=2 (read_user failed); write errno+addr payload at start; header keeps reserved_len
                    self.builder.position_at_end(err_block);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ReadError as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // write errno at [0..4]
                    let i32_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "errno_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to cast errno ptr: {e}"))
                        })?;
                    self.builder.build_store(i32_ptr, ret).map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store errno: {e}"))
                    })?;
                    // write addr at [4..12]
                    let addr_ptr_i8 = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[i32_type.const_int(4, false)],
                                "addr_ptr_i8",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to get addr gep: {e}"))
                            })?
                    };
                    let addr_ptr = self
                        .builder
                        .build_pointer_cast(
                            addr_ptr_i8,
                            self.context.ptr_type(AddressSpace::default()),
                            "addr_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to cast addr ptr: {e}"))
                        })?;
                    let src_as_i64 = src_addr;
                    self.builder
                        .build_store(addr_ptr, src_as_i64)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store addr: {e}"))
                        })?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // OK branch: success or truncated (header keeps reserved_len)
                    self.builder.position_at_end(ok_block);
                    if a.data_len < dwarf_type.size() as usize {
                        self.builder
                            .build_store(
                                apl_ptr,
                                self.context
                                    .i8_type()
                                    .const_int(VariableStatus::Truncated as u64, false),
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        self.mark_any_success()?;
                        self.mark_any_fail()?;
                    } else {
                        self.mark_any_success()?;
                    }
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    self.builder.position_at_end(cont2_block);
                }
                ComplexArgSource::AddressValue {
                    eval_result,
                    module_for_offsets,
                } => {
                    // Compute address (apply ASLR if link-time address) and store as 8 bytes
                    let addr = self.evaluation_result_to_address_with_hint(
                        eval_result,
                        Some(apl_ptr),
                        module_for_offsets.as_deref(),
                    )?;
                    let cast_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "addr_store_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_store(cast_ptr, addr)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // header already set to reserved_len (8)
                }
            }
            // Advance compile-time offset by header_len + reserved_len
            offset += 2 + 2 + 1 + 1 + a.access_path.len() + 2 + reserved_len;
        }

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }

    /// Generate eBPF code for PrintStringIndex instruction
    pub fn generate_print_string_index(&mut self, string_index: u16) -> Result<()> {
        info!(
            "Generating PrintStringIndex instruction: index={}",
            string_index
        );

        // Allocate instruction structure on eBPF stack
        // Reserve space in accumulation buffer for this instruction
        let inst_buffer = self.reserve_instruction_region(
            (std::mem::size_of::<InstructionHeader>() + std::mem::size_of::<PrintStringIndexData>())
                as u64,
        );

        // Clear memory with static size
        let _inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<PrintStringIndexData>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>())
                as u64,
            false,
        );
        // Avoid memset on eBPF; global buffer is zero-initialized and we write fields explicitly.

        // Fill instruction header using byte offsets
        // inst_type at offset 0 (first field of InstructionHeader)
        let inst_type_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, inst_type) as u64,
                        false,
                    )],
                    "inst_type_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get inst_type GEP: {e}")))?
        };
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintStringIndex as u64, false);
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, data_length) as u64,
                        false,
                    )],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(std::mem::size_of::<PrintStringIndexData>() as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Fill string index data (after InstructionHeader)
        let string_index_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(std::mem::size_of::<InstructionHeader>() as u64, false)],
                    "string_index_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get string_index GEP: {e}"))
                })?
        };
        let string_index_i16_ptr = self
            .builder
            .build_pointer_cast(
                string_index_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "string_index_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast string_index ptr: {e}"))
            })?;
        let string_index_val = self
            .context
            .i16_type()
            .const_int(string_index as u64, false);
        self.builder
            .build_store(string_index_i16_ptr, string_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store string_index: {e}")))?;

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }

    /// Generate ExprError instruction with expression string index and error code/flags
    pub fn generate_expr_error(
        &mut self,
        expr_string_index: u16,
        error_code_iv: inkwell::values::IntValue<'ctx>,
        flags_iv: inkwell::values::IntValue<'ctx>,
        failing_addr_iv: inkwell::values::IntValue<'ctx>,
    ) -> Result<()> {
        // Reserve space in accumulation buffer for this instruction
        let inst_buffer = self.reserve_instruction_region(
            (std::mem::size_of::<InstructionHeader>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::ExprErrorData>())
                as u64,
        );

        // Store instruction type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::ExprError as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // data_length
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, data_length) as u64,
                        false,
                    )],
                    "exprerr_data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "exprerr_data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let data_length_val = self.context.i16_type().const_int(
            std::mem::size_of::<ghostscope_protocol::trace_event::ExprErrorData>() as u64,
            false,
        );
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Payload fields after header
        // string_index at offset sizeof(InstructionHeader) + 0 (u16)
        let si_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(std::mem::size_of::<InstructionHeader>() as u64, false)],
                    "exprerr_si_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get string_index GEP: {e}"))
                })?
        };
        let si_i16_ptr = self
            .builder
            .build_pointer_cast(
                si_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "exprerr_si_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast string_index ptr: {e}"))
            })?;
        let si_val = self
            .context
            .i16_type()
            .const_int(expr_string_index as u64, false);
        self.builder
            .build_store(si_i16_ptr, si_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store string_index: {e}")))?;

        // error_code at +2, flags at +3
        let ec_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int((std::mem::size_of::<InstructionHeader>() + 2) as u64, false)],
                    "exprerr_ec_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get error_code GEP: {e}"))
                })?
        };
        // Truncate/extend runtime error code to i8
        let ec_i8 = if error_code_iv.get_type().get_bit_width() == 8 {
            error_code_iv
        } else if error_code_iv.get_type().get_bit_width() > 8 {
            self.builder
                .build_int_truncate(error_code_iv, self.context.i8_type(), "ec_trunc")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            self.builder
                .build_int_z_extend(error_code_iv, self.context.i8_type(), "ec_zext")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(ec_ptr, ec_i8)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store error_code: {e}")))?;
        let fl_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int((std::mem::size_of::<InstructionHeader>() + 3) as u64, false)],
                    "exprerr_flags_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get flags GEP: {e}")))?
        };
        // Truncate/extend runtime flags to i8
        let fl_i8 = if flags_iv.get_type().get_bit_width() == 8 {
            flags_iv
        } else if flags_iv.get_type().get_bit_width() > 8 {
            self.builder
                .build_int_truncate(flags_iv, self.context.i8_type(), "fl_trunc")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            self.builder
                .build_int_z_extend(flags_iv, self.context.i8_type(), "fl_zext")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(fl_ptr, fl_i8)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store flags: {e}")))?;

        // failing_addr at +4 (u64)
        let addr_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int((std::mem::size_of::<InstructionHeader>() + 4) as u64, false)],
                    "exprerr_addr_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get addr GEP: {e}")))?
        };
        let addr_i64 = if failing_addr_iv.get_type().get_bit_width() == 64 {
            failing_addr_iv
        } else if failing_addr_iv.get_type().get_bit_width() > 64 {
            self.builder
                .build_int_truncate(failing_addr_iv, self.context.i64_type(), "addr_trunc")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            self.builder
                .build_int_z_extend(failing_addr_iv, self.context.i64_type(), "addr_zext")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        let addr_ptr_cast = self
            .builder
            .build_pointer_cast(
                addr_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "exprerr_addr_i64_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(addr_ptr_cast, addr_i64)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store failing_addr: {e}")))?;

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }

    /// Generate eBPF code for PrintVariableIndex instruction
    pub fn generate_print_variable_index(
        &mut self,
        var_name_index: u16,
        type_encoding: TypeKind,
        var_name: &str,
    ) -> Result<()> {
        info!(
            "Generating PrintVariableIndex instruction: var_name_index={}, type={:?}, var_name={}",
            var_name_index, type_encoding, var_name
        );

        // Resolve type_index from DWARF if available; otherwise synthesize from TypeKind
        let type_index = match self.query_dwarf_for_variable(var_name)? {
            Some(var) => match var.dwarf_type {
                Some(ref t) => self.trace_context.add_type(t.clone()),
                None => self.add_synthesized_type_index_for_kind(type_encoding),
            },
            None => {
                // Variable not found via DWARF; fall back to synthesized type info based on TypeKind
                self.add_synthesized_type_index_for_kind(type_encoding)
            }
        };

        match self.resolve_variable_value(var_name, type_encoding) {
            Ok(var_data) => self.generate_successful_variable_instruction(
                var_name_index,
                type_encoding,
                type_index,
                var_data,
            ),
            Err(e) => Err(e),
        }
    }

    /// Generate successful variable instruction with data
    fn generate_successful_variable_instruction(
        &mut self,
        var_name_index: u16,
        type_encoding: TypeKind,
        type_index: u16,
        var_data: BasicValueEnum<'ctx>,
    ) -> Result<()> {
        // Determine data size based on type
        let data_size = match type_encoding {
            TypeKind::U8 | TypeKind::I8 | TypeKind::Bool | TypeKind::Char => 1,
            TypeKind::U16 | TypeKind::I16 => 2,
            TypeKind::U32 | TypeKind::I32 | TypeKind::F32 => 4,
            TypeKind::U64 | TypeKind::I64 | TypeKind::F64 | TypeKind::Pointer => 8,
            _ => 8, // Default to 8 bytes for complex types
        };

        // Reserve space directly in per-CPU accumulation buffer
        let inst_buffer = self.reserve_instruction_region(
            (std::mem::size_of::<InstructionHeader>()
                + std::mem::size_of::<PrintVariableIndexData>()
                + data_size as usize) as u64,
        );

        // Avoid memset; global buffer is zero-initialized

        // Store instruction type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintVariableIndex as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // Store data_length field of InstructionHeader
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, data_length) as u64,
                        false,
                    )],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let total_data_length = std::mem::size_of::<PrintVariableIndexData>() + data_size as usize;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(total_data_length as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Write PrintVariableIndexData after InstructionHeader
        let variable_data_start = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(std::mem::size_of::<InstructionHeader>() as u64, false)],
                    "variable_data_start",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get variable_data_start GEP: {e}"))
                })?
        };

        // Store var_name_index using correct offset
        let var_name_index_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, var_name_index) as u64,
                        false,
                    )],
                    "var_name_index_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {e}"))
                })?
        };
        let var_name_index_i16_ptr = self
            .builder
            .build_pointer_cast(
                var_name_index_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {e}"))
            })?;
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(var_name_index as u64, false);
        self.builder
            .build_store(var_name_index_i16_ptr, var_name_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store var_name_index: {e}")))?;

        // Store type_encoding using correct offset
        let type_encoding_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, type_encoding) as u64,
                        false,
                    )],
                    "type_encoding_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_encoding GEP: {e}"))
                })?
        };
        let type_encoding_val = self
            .context
            .i8_type()
            .const_int(type_encoding as u8 as u64, false);
        self.builder
            .build_store(type_encoding_ptr, type_encoding_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_encoding: {e}")))?;

        // Store data_len using correct offset
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, data_len) as u64,
                        false,
                    )],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data_len GEP: {e}")))?
        };
        let data_len_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {e}")))?;
        let data_len_val = self.context.i16_type().const_int(data_size as u64, false); // Store as u16
        self.builder
            .build_store(data_len_i16_ptr, data_len_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;

        // Store type_index using correct offset
        let type_index_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, type_index) as u64,
                        false,
                    )],
                    "type_index_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {e}"))
                })?
        };
        let type_index_i16_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {e}")))?;
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        self.builder
            .build_store(type_index_i16_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {e}")))?;

        // Store status (set to 0)
        let reserved_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, status) as u64,
                        false,
                    )],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {e}")))?
        };
        let reserved_val = self
            .context
            .i8_type()
            .const_int(VariableStatus::Ok as u64, false);
        self.builder
            .build_store(reserved_ptr, reserved_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

        // Store actual variable data after PrintVariableIndexData structure
        let var_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self
                        .context
                        .i32_type()
                        .const_int(std::mem::size_of::<PrintVariableIndexData>() as u64, false)],
                    "var_data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get var_data GEP: {e}")))?
        };

        // Store the runtime variable value based on data size
        // The var_data contains the LLVM IR value (from register/memory access)
        match data_size {
            1 => {
                // Store as i8
                let truncated = match var_data {
                    BasicValueEnum::IntValue(int_val) => self
                        .builder
                        .build_int_truncate(int_val, self.context.i8_type(), "truncated_i8")
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to truncate to i8: {e}"))
                        })?,
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer value for integer type".to_string(),
                        ));
                    }
                };
                self.builder
                    .build_store(var_data_ptr, truncated)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store i8 data: {e}"))
                    })?;
            }
            2 => {
                // Store as i16
                let truncated = match var_data {
                    BasicValueEnum::IntValue(int_val) => self
                        .builder
                        .build_int_truncate(int_val, self.context.i16_type(), "truncated_i16")
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to truncate to i16: {e}"))
                        })?,
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer value for integer type".to_string(),
                        ));
                    }
                };
                let i16_ptr = self
                    .builder
                    .build_pointer_cast(
                        var_data_ptr,
                        self.context.ptr_type(AddressSpace::default()),
                        "i16_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to cast to i16 ptr: {e}"))
                    })?;
                self.builder.build_store(i16_ptr, truncated).map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to store i16 data: {e}"))
                })?;
            }
            4 => {
                // Store as i32 or f32
                match var_data {
                    BasicValueEnum::IntValue(int_val) => {
                        let truncated = self
                            .builder
                            .build_int_truncate(int_val, self.context.i32_type(), "truncated_i32")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to truncate to i32: {e}"))
                            })?;
                        let i32_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i32_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i32 ptr: {e}"))
                            })?;
                        self.builder.build_store(i32_ptr, truncated).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i32 data: {e}"))
                        })?;
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        let f32_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "f32_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to f32 ptr: {e}"))
                            })?;
                        self.builder.build_store(f32_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f32 data: {e}"))
                        })?;
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer or float value for 4-byte type".to_string(),
                        ));
                    }
                }
            }
            8 => {
                // Store as i64, f64, or pointer
                match var_data {
                    BasicValueEnum::IntValue(int_val) => {
                        let i64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {e}"))
                            })?;
                        self.builder.build_store(i64_ptr, int_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i64 data: {e}"))
                        })?;
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        let f64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "f64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to f64 ptr: {e}"))
                            })?;
                        self.builder.build_store(f64_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f64 data: {e}"))
                        })?;
                    }
                    BasicValueEnum::PointerValue(ptr_val) => {
                        // Store pointer as u64
                        let ptr_int = self
                            .builder
                            .build_ptr_to_int(ptr_val, self.context.i64_type(), "ptr_as_int")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to convert ptr to int: {e}"
                                ))
                            })?;
                        let i64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {e}"))
                            })?;
                        self.builder.build_store(i64_ptr, ptr_int).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store pointer data: {e}"))
                        })?;
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer, float, or pointer value for 8-byte type".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(CodeGenError::LLVMError(format!(
                    "Unsupported data size: {data_size}"
                )));
            }
        }

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }

    // PrintVariableError instruction has been removed; compile-time errors are returned as Err,
    // runtime errors are carried via per-variable status in Print* instructions.

    /// Generate Backtrace instruction
    pub fn generate_backtrace_instruction(&mut self, depth: u8) -> Result<()> {
        info!("Generating Backtrace instruction: depth={}", depth);

        // Reserve space directly for Backtrace instruction
        let inst_buffer = self.reserve_instruction_region(
            (std::mem::size_of::<InstructionHeader>() + std::mem::size_of::<BacktraceData>())
                as u64,
        );

        // Write InstructionHeader.inst_type
        let inst_type_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, inst_type) as u64,
                        false,
                    )],
                    "bt_inst_type_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get inst_type GEP: {e}")))?
        };
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::Backtrace as u64, false);
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // Write InstructionHeader.data_length (u16)
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, data_length) as u64,
                        false,
                    )],
                    "bt_data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "bt_data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let dl_val = self
            .context
            .i16_type()
            .const_int(std::mem::size_of::<BacktraceData>() as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, dl_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Already accumulated; EndInstruction will send the whole event. Depth currently unused at BPF level.
        Ok(())
    }

    /// Resolve variable value from script variables first, then DWARF
    fn resolve_variable_value(
        &mut self,
        var_name: &str,
        type_encoding: TypeKind,
    ) -> Result<BasicValueEnum<'ctx>> {
        info!(
            "Resolving variable value: {} ({:?})",
            var_name, type_encoding
        );

        // 1) Script variable first
        if self.variable_exists(var_name) {
            info!("Found script variable for '{}', loading value", var_name);
            return self.load_variable(var_name);
        }

        // 2) DWARF variable as fallback
        match self.query_dwarf_for_variable(var_name)? {
            Some(var_info) => {
                info!(
                    "Found DWARF variable: {} = {:?}",
                    var_name, var_info.evaluation_result
                );

                // Require DWARF type information
                let dwarf_type = var_info.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError(format!(
                        "Variable '{var_name}' has no type information in DWARF"
                    ))
                })?;

                let compile_context = self.get_compile_time_context()?;
                self.evaluate_result_to_llvm_value(
                    &var_info.evaluation_result,
                    dwarf_type,
                    var_name,
                    compile_context.pc_address,
                )
            }
            None => {
                let compile_context = self.get_compile_time_context()?;
                warn!(
                    "Variable '{}' not found in DWARF at address 0x{:x}",
                    var_name, compile_context.pc_address
                );
                Err(CodeGenError::VariableNotFound(var_name.to_string()))
            }
        }
    }

    /// Generate PrintComplexVariable instruction and copy data at runtime using probe_read_user
    fn generate_print_complex_variable_runtime(
        &mut self,
        meta: PrintVarRuntimeMeta,
        eval_result: &ghostscope_dwarf::EvaluationResult,
        dwarf_type: &ghostscope_dwarf::TypeInfo,
        module_hint: Option<&str>,
    ) -> Result<()> {
        tracing::trace!(
            var_name_index = meta.var_name_index,
            type_index = meta.type_index,
            access_path = %meta.access_path,
            type_size = dwarf_type.size(),
            data_len_limit = meta.data_len_limit,
            eval = ?eval_result,
            "generate_print_complex_variable_runtime: begin"
        );
        // Compute sizes first, then reserve instruction region directly in accumulation buffer

        // Compute sizes
        let access_path_bytes = meta.access_path.as_bytes();
        let access_path_len = std::cmp::min(access_path_bytes.len(), 255); // u8 max
        let type_size = dwarf_type.size() as usize;
        let mut data_len = std::cmp::min(type_size, meta.data_len_limit);
        if data_len > u16::MAX as usize {
            data_len = u16::MAX as usize;
        }

        let header_size = std::mem::size_of::<InstructionHeader>();
        let data_struct_size = std::mem::size_of::<PrintComplexVariableData>();
        // Reserve enough space to hold either the value (read_len) or an error payload (12 bytes)
        let reserved_payload = std::cmp::max(data_len, 12);
        let total_data_length = data_struct_size + access_path_len + reserved_payload;
        let total_size = header_size + total_data_length;
        tracing::trace!(
            header_size,
            data_struct_size,
            access_path_len,
            data_len,
            total_data_length,
            total_size,
            "generate_print_complex_variable_runtime: sizes computed"
        );

        // Reserve space now that sizes are known
        let inst_buffer = self.reserve_instruction_region(total_size as u64);

        // Avoid memset; reserved map value bytes are zero-initialized

        // Write InstructionHeader.inst_type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;
        tracing::trace!(
            "generate_print_complex_variable_runtime: wrote inst_type=PrintComplexVariable"
        );

        // Write InstructionHeader
        // data_length field (u16) at offset 1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        self.builder
            .build_store(
                data_length_ptr_cast,
                self.context
                    .i16_type()
                    .const_int(total_data_length as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;
        tracing::trace!(
            data_length = total_data_length,
            "generate_print_complex_variable_runtime: wrote data_length"
        );

        // Data pointer (after header)
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(header_size as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {e}")))?
        };

        // var_name_index (u16)
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(meta.var_name_index as u64, false);
        // Store var_name_index at offset offsetof(PrintComplexVariableData, var_name_index)
        let var_name_index_off =
            std::mem::offset_of!(PrintComplexVariableData, var_name_index) as u64;
        let var_name_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(var_name_index_off, false)],
                    "var_name_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {e}"))
                })?
        };
        let var_name_index_ptr_i16 = self
            .builder
            .build_pointer_cast(
                var_name_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {e}"))
            })?;
        self.builder
            .build_store(var_name_index_ptr_i16, var_name_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store var_name_index: {e}")))?;
        tracing::trace!(
            var_name_index = meta.var_name_index,
            "generate_print_complex_variable_runtime: wrote var_name_index"
        );

        // type_index (u16) right after var_name_index
        // type_index at offset offsetof(PrintComplexVariableData, type_index) = 2
        let type_index_offset = std::mem::offset_of!(PrintComplexVariableData, type_index) as u64;
        let type_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(type_index_offset, false)],
                    "type_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {e}"))
                })?
        };
        let type_index_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {e}")))?;
        let type_index_val = self
            .context
            .i16_type()
            .const_int(meta.type_index as u64, false);
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {e}")))?;
        tracing::trace!(
            type_index = meta.type_index,
            "generate_print_complex_variable_runtime: wrote type_index"
        );

        // access_path_len (u8)
        // access_path_len at offset offsetof(..., access_path_len)
        let access_path_len_off =
            std::mem::offset_of!(PrintComplexVariableData, access_path_len) as u64;
        let access_path_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len_off, false)],
                    "access_path_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {e}"))
                })?
        };
        self.builder
            .build_store(
                access_path_len_ptr,
                self.context
                    .i8_type()
                    .const_int(access_path_len as u64, false),
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {e}"))
            })?;
        tracing::trace!(
            access_path_len,
            "generate_print_complex_variable_runtime: wrote access_path_len"
        );

        // status (u8) at offset offsetof(..., status)
        let status_off = std::mem::offset_of!(PrintComplexVariableData, status) as u64;
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(status_off, false)],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {e}")))?
        };
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::Ok as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

        // (Optimized-out handling moved below after data_len pointer is available)

        // data_len (u16)
        let data_len_off = std::mem::offset_of!(PrintComplexVariableData, data_len) as u64;
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(data_len_off, false)],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data_len GEP: {e}")))?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {e}")))?;
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(data_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;
        tracing::trace!(
            data_len,
            "generate_print_complex_variable_runtime: wrote data_len"
        );

        // Optimized-out case is handled earlier by resolving to an OptimizedOut type and ImmediateBytes path.

        // access_path bytes start after PrintComplexVariableData
        let access_path_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(
                        std::mem::size_of::<PrintComplexVariableData>() as u64,
                        false,
                    )],
                    "access_path_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path GEP: {e}"))
                })?
        };

        // Copy access path bytes
        for (i, &byte) in access_path_bytes.iter().enumerate().take(access_path_len) {
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        access_path_ptr,
                        &[self.context.i32_type().const_int(i as u64, false)],
                        &format!("access_path_byte_{i}"),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get access_path byte GEP: {e}"))
                    })?
            };
            let byte_val = self.context.i8_type().const_int(byte as u64, false);
            self.builder.build_store(byte_ptr, byte_val).map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path byte: {e}"))
            })?;
        }
        if access_path_len > 0 {
            tracing::trace!("generate_print_complex_variable_runtime: wrote access_path bytes");
        }

        // Variable data starts after access_path
        let variable_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    access_path_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len as u64, false)],
                    "variable_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get variable_data GEP: {e}"))
                })?
        };

        // Compute source address with ASLR-aware helper, honoring module hint
        // Prefer a previously recorded module path for offsets; fall back handled in helper
        let src_addr = self.evaluation_result_to_address_with_hint(
            eval_result,
            Some(status_ptr),
            module_hint,
        )?;
        tracing::trace!(src_addr = %{src_addr}, "generate_print_complex_variable_runtime: computed src_addr");

        // Setup common types and casts
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let dst_ptr = self
            .builder
            .build_bit_cast(variable_data_ptr, ptr_type, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let size_val = i32_type.const_int(data_len as u64, false);
        let src_ptr = self
            .builder
            .build_int_to_ptr(src_addr, ptr_type, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let offsets_found = self.load_offsets_found_flag()?;
        let current_block = self.builder.get_insert_block().unwrap();
        let current_fn = current_block.get_parent().unwrap();
        let cont_block = self.context.append_basic_block(current_fn, "after_read");
        let skip_block = self.context.append_basic_block(current_fn, "offsets_skip");
        let found_block = self.context.append_basic_block(current_fn, "offsets_found");
        self.builder
            .build_conditional_branch(offsets_found, found_block, skip_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(skip_block);
        self.mark_any_fail()?;
        self.builder
            .build_store(data_len_ptr_cast, self.context.i16_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(found_block);

        // Branch: NULL deref if src_addr == 0
        let zero64 = i64_type.const_zero();
        let is_null = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, src_addr, zero64, "is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let null_block = self.context.append_basic_block(current_fn, "null_deref");
        let read_block = self.context.append_basic_block(current_fn, "read_user");
        self.builder
            .build_conditional_branch(is_null, null_block, read_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // NULL path
        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // data_len = 0
        self.builder
            .build_store(data_len_ptr_cast, self.context.i16_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // mark fail
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Read path
        self.builder.position_at_end(read_block);
        let ret = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[dst_ptr, size_val.into(), src_ptr.into()],
                i32_type.into(),
                "probe_read_user",
            )?
            .into_int_value();
        let is_err = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::SLT,
                ret,
                i32_type.const_zero(),
                "ret_lt_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let err_block = self.context.append_basic_block(current_fn, "read_err");
        let ok_block = self.context.append_basic_block(current_fn, "read_ok");
        self.builder
            .build_conditional_branch(is_err, err_block, ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Error: status=2 (read_user failed); attach errno+addr payload and set data_len=12
        self.builder.position_at_end(err_block);
        // Only set ReadError if status is still Ok (preserve OffsetsUnavailable etc.)
        let cur_status1 = self
            .builder
            .build_load(self.context.i8_type(), status_ptr, "cur_status1")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_ok1 = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                cur_status1.into_int_value(),
                self.context.i8_type().const_zero(),
                "status_is_ok1",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let readerr_val = self
            .context
            .i8_type()
            .const_int(VariableStatus::ReadError as u64, false)
            .into();
        let new_status1 = self
            .builder
            .build_select(is_ok1, readerr_val, cur_status1, "status_after_readerr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(status_ptr, new_status1)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // data_len = 12 (errno:i32 + addr:u64)
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(12, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // write errno at [0..4]
        let errno_ptr = self
            .builder
            .build_pointer_cast(
                variable_data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "errno_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast errno ptr: {e}")))?;
        self.builder
            .build_store(errno_ptr, ret)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store errno: {e}")))?;
        // write addr at [4..12]
        let addr_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_ptr,
                    &[self.context.i32_type().const_int(4, false)],
                    "addr_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get addr GEP: {e}")))?
        };
        let addr_ptr = self
            .builder
            .build_pointer_cast(
                addr_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "addr_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast addr ptr: {e}")))?;
        self.builder
            .build_store(addr_ptr, src_addr)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store addr: {e}")))?;
        // mark fail
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // OK path: status=0; optional truncated if data_len_limit < dwarf_type.size()
        self.builder.position_at_end(ok_block);
        if data_len < dwarf_type.size() as usize {
            // truncated
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            // mark both success and fail
            self.mark_any_success()?;
            self.mark_any_fail()?;
        } else {
            // success
            self.mark_any_success()?;
        }
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Continue
        self.builder.position_at_end(cont_block);

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompileOptions;

    #[test]
    fn computed_int_store_i64_compiles() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");
        // print {} with a pure script integer expression triggers ComputedInt path
        let expr = crate::script::Expr::BinaryOp {
            left: Box::new(crate::script::Expr::Int(41)),
            op: crate::script::BinaryOp::Add,
            right: Box::new(crate::script::Expr::Int(1)),
        };
        let stmt =
            crate::script::Statement::Print(crate::script::PrintStatement::ComplexVariable(expr));
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "test_func", &[stmt], None, None, None);
        assert!(res.is_ok(), "Compilation failed: {:?}", res.err());
    }

    #[test]
    fn computed_int_in_format_compiles() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");
        // formatted print with expression argument should also route into ComputedInt path
        let expr = crate::script::Expr::BinaryOp {
            left: Box::new(crate::script::Expr::Int(1)),
            op: crate::script::BinaryOp::Add,
            right: Box::new(crate::script::Expr::Int(2)),
        };
        let stmt = crate::script::Statement::Print(crate::script::PrintStatement::Formatted {
            format: "sum:{}".to_string(),
            args: vec![expr],
        });
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "test_fmt", &[stmt], None, None, None);
        assert!(res.is_ok(), "Compilation failed: {:?}", res.err());
    }

    #[test]
    fn memcmp_rejects_script_pointer_variable_now() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");

        // let p = "A";  // script pointer to const string (no longer accepted as memcmp arg)
        let decl = crate::script::Statement::VarDeclaration {
            name: "p".to_string(),
            value: crate::script::Expr::String("A".to_string()),
        };

        // if memcmp(p, hex("41"), 1) { print "OK"; }
        let if_stmt = crate::script::Statement::If {
            condition: crate::script::Expr::BuiltinCall {
                name: "memcmp".to_string(),
                args: vec![
                    crate::script::Expr::Variable("p".to_string()),
                    crate::script::Expr::BuiltinCall {
                        name: "hex".to_string(),
                        args: vec![crate::script::Expr::String("41".to_string())],
                    },
                    crate::script::Expr::Int(1),
                ],
            },
            then_body: vec![crate::script::Statement::Print(
                crate::script::PrintStatement::String("OK".to_string()),
            )],
            else_body: None,
        };

        let program = crate::script::Program::new();
        let res = ctx.compile_program(
            &program,
            "test_memcmp_ptr",
            &[decl, if_stmt],
            None,
            None,
            None,
        );
        assert!(
            res.is_err(),
            "Expected type error for script pointer variable in memcmp"
        );
    }

    #[test]
    fn strncmp_requires_string_on_one_side_error_message() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // strncmp(42, 43, 2) -> neither side is string (literal/var); expect type error
        let stmt = crate::script::Statement::If {
            condition: crate::script::Expr::BuiltinCall {
                name: "strncmp".to_string(),
                args: vec![
                    crate::script::Expr::Int(42),
                    crate::script::Expr::Int(43),
                    crate::script::Expr::Int(2),
                ],
            },
            then_body: vec![crate::script::Statement::Print(
                crate::script::PrintStatement::String("OK".to_string()),
            )],
            else_body: None,
        };
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "test_strncmp_err", &[stmt], None, None, None);
        assert!(
            res.is_err(),
            "expected error when neither side is string (got {res:?})",
        );
        let msg = format!("{:?}", res.err());
        assert!(msg.contains("strncmp requires at least one string argument"));
    }

    // No test needed here for string var copy rejection; current semantics allow
    // let s = "A"; let p = s; as a string-to-string assignment.

    #[test]
    fn immutable_variable_redeclaration_rejected() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // let x = 1; let x = 2;  (same trace block)
        let d1 = crate::script::Statement::VarDeclaration {
            name: "x".to_string(),
            value: crate::script::Expr::Int(1),
        };
        let d2 = crate::script::Statement::VarDeclaration {
            name: "x".to_string(),
            value: crate::script::Expr::Int(2),
        };
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "immut", &[d1, d2], None, None, None);
        assert!(res.is_err(), "expected immutability error, got {res:?}");
        let msg = format!("{:?}", res.err());
        assert!(
            msg.contains("Redeclaration in the same scope") || msg.contains("immutable variable"),
            "unexpected error msg: {msg}"
        );
    }

    #[test]
    fn immutable_alias_rebinding_rejected() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // let p = &arr[0]; let p = &arr[0];
        let a1 = crate::script::Statement::AliasDeclaration {
            name: "p".to_string(),
            target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
                "arr".to_string(),
            ))),
        };
        let a2 = crate::script::Statement::AliasDeclaration {
            name: "p".to_string(),
            target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
                "arr".to_string(),
            ))),
        };
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "immut_alias", &[a1, a2], None, None, None);
        assert!(
            res.is_err(),
            "expected immutability error for alias, got {res:?}"
        );
    }

    #[test]
    fn alias_to_alias_with_const_offset_is_alias_variable() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");
        // let base = &buf[0]; let tail = base + 16;
        let s1 = crate::script::Statement::AliasDeclaration {
            name: "base".to_string(),
            target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::ArrayAccess(
                Box::new(crate::script::Expr::Variable("buf".to_string())),
                Box::new(crate::script::Expr::Int(0)),
            ))),
        };
        let s2 = crate::script::Statement::VarDeclaration {
            name: "tail".to_string(),
            value: crate::script::Expr::BinaryOp {
                left: Box::new(crate::script::Expr::Variable("base".to_string())),
                op: crate::script::BinaryOp::Add,
                right: Box::new(crate::script::Expr::Int(16)),
            },
        };
        let program = crate::script::Program::new();
        // Should treat tail as alias (not as value), thus compile_program succeeds
        let res = ctx.compile_program(&program, "alias_stage", &[s1, s2], None, None, None);
        assert!(res.is_ok(), "expected alias-to-alias staging to compile");
    }

    #[test]
    fn alias_to_alias_copy_is_alias_variable() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");
        // let a = &G_STATE.lib; let b = a;
        let a = crate::script::Statement::AliasDeclaration {
            name: "a".to_string(),
            target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::MemberAccess(
                Box::new(crate::script::Expr::Variable("G_STATE".to_string())),
                "lib".to_string(),
            ))),
        };
        let b = crate::script::Statement::VarDeclaration {
            name: "b".to_string(),
            value: crate::script::Expr::Variable("a".to_string()),
        };
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "alias_copy", &[a, b], None, None, None);
        assert!(res.is_ok(), "expected alias-to-alias copy to compile");
    }

    #[test]
    fn alias_self_reference_is_rejected_with_cycle_error() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // let a = &a; print a;
        let a = crate::script::Statement::AliasDeclaration {
            name: "a".to_string(),
            target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
                "a".to_string(),
            ))),
        };
        let p = crate::script::Statement::Print(crate::script::PrintStatement::ComplexVariable(
            crate::script::Expr::Variable("a".to_string()),
        ));
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "alias_self", &[a, p], None, None, None);
        assert!(res.is_err(), "expected cycle error, got {res:?}");
        let msg = format!("{:?}", res.err());
        assert!(
            msg.contains("alias cycle") || msg.contains("depth exceeded"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn alias_mutual_cycle_is_rejected_with_cycle_error() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // let a = &b; let b = &a; print a;
        let a = crate::script::Statement::AliasDeclaration {
            name: "a".to_string(),
            target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
                "b".to_string(),
            ))),
        };
        let b = crate::script::Statement::AliasDeclaration {
            name: "b".to_string(),
            target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
                "a".to_string(),
            ))),
        };
        let p = crate::script::Statement::Print(crate::script::PrintStatement::ComplexVariable(
            crate::script::Expr::Variable("a".to_string()),
        ));
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "alias_cycle", &[a, b, p], None, None, None);
        assert!(res.is_err(), "expected cycle error, got {res:?}");
        let msg = format!("{:?}", res.err());
        assert!(
            msg.contains("alias cycle") || msg.contains("depth exceeded"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn strncmp_folds_with_script_string_and_literal_true() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // Prepare: let s = "ABC";
        let decl = crate::script::Statement::VarDeclaration {
            name: "s".to_string(),
            value: crate::script::Expr::String("ABC".to_string()),
        };
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "decl", &[decl], None, None, None);
        assert!(res.is_ok());

        // Expression: strncmp(s, "ABD", 2) -> true
        let expr = crate::script::Expr::BuiltinCall {
            name: "strncmp".to_string(),
            args: vec![
                crate::script::Expr::Variable("s".to_string()),
                crate::script::Expr::String("ABD".to_string()),
                crate::script::Expr::Int(2),
            ],
        };
        let v = ctx.compile_expr(&expr).expect("compile expr");
        match v {
            inkwell::values::BasicValueEnum::IntValue(iv) => {
                assert_eq!(iv.get_type().get_bit_width(), 1);
                // true expected (string repr may vary across LLVM versions, check both forms)
                let s = format!("{iv}");
                assert!(s.contains("i1 true") || s.contains("true"));
            }
            other => panic!("expected IntValue i1, got {other:?}"),
        }
    }

    #[test]
    fn starts_with_folds_with_two_literals() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // Expression: starts_with("abcdef", "abc") -> true
        let expr = crate::script::Expr::BuiltinCall {
            name: "starts_with".to_string(),
            args: vec![
                crate::script::Expr::String("abcdef".to_string()),
                crate::script::Expr::String("abc".to_string()),
            ],
        };
        let v = ctx.compile_expr(&expr).expect("compile expr");
        match v {
            inkwell::values::BasicValueEnum::IntValue(iv) => {
                assert_eq!(iv.get_type().get_bit_width(), 1);
                let s = format!("{iv}");
                assert!(s.contains("i1 true") || s.contains("true"));
            }
            _ => panic!("expected i1"),
        }
    }

    #[test]
    fn starts_with_requires_one_string_side_error() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // Neither side is string
        let expr = crate::script::Expr::BuiltinCall {
            name: "starts_with".to_string(),
            args: vec![crate::script::Expr::Int(1), crate::script::Expr::Int(2)],
        };
        let res = ctx.compile_expr(&expr);
        assert!(res.is_err(), "expected error");
        let msg = format!("{:?}", res.err());
        assert!(msg.contains("starts_with requires at least one string argument"));
    }

    #[test]
    fn shadowing_rejected_in_inner_scope() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // let x = 1; { let x = 2; }
        let d1 = crate::script::Statement::VarDeclaration {
            name: "x".to_string(),
            value: crate::script::Expr::Int(1),
        };
        let inner =
            crate::script::Statement::Block(vec![crate::script::Statement::VarDeclaration {
                name: "x".to_string(),
                value: crate::script::Expr::Int(2),
            }]);
        let program = crate::script::Program::new();
        let res = ctx.compile_program(&program, "shadow", &[d1, inner], None, None, None);
        assert!(res.is_err(), "expected shadowing error");
        let msg = format!("{:?}", res.err());
        assert!(
            msg.contains("Shadowing is not allowed") || msg.contains("shadow"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn out_of_scope_use_is_rejected() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

        // { let y = 2; } print y;  -> y is out of scope
        let block =
            crate::script::Statement::Block(vec![crate::script::Statement::VarDeclaration {
                name: "y".to_string(),
                value: crate::script::Expr::Int(2),
            }]);
        let print_y = crate::script::Statement::Print(crate::script::PrintStatement::Variable(
            "y".to_string(),
        ));
        let program = crate::script::Program::new();
        let res = ctx.compile_program(
            &program,
            "out_of_scope",
            &[block, print_y],
            None,
            None,
            None,
        );
        assert!(
            res.is_err(),
            "expected out-of-scope or missing analyzer error"
        );
    }

    #[test]
    fn memcmp_rejects_bare_integer_pointer_argument() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");

        // let q = 0xdeadbeef;  // integer, not a pointer value
        let decl = crate::script::Statement::VarDeclaration {
            name: "q".to_string(),
            value: crate::script::Expr::Int(0xdeadbeef),
        };

        // if memcmp(q, hex("00"), 1) { print "X"; }
        let if_stmt = crate::script::Statement::If {
            condition: crate::script::Expr::BuiltinCall {
                name: "memcmp".to_string(),
                args: vec![
                    crate::script::Expr::Variable("q".to_string()),
                    crate::script::Expr::BuiltinCall {
                        name: "hex".to_string(),
                        args: vec![crate::script::Expr::String("00".to_string())],
                    },
                    crate::script::Expr::Int(1),
                ],
            },
            then_body: vec![crate::script::Statement::Print(
                crate::script::PrintStatement::String("X".to_string()),
            )],
            else_body: None,
        };

        let program = crate::script::Program::new();
        let res = ctx.compile_program(
            &program,
            "test_memcmp_int_ptr",
            &[decl, if_stmt],
            None,
            None,
            None,
        );
        assert!(res.is_err(), "Expected compilation error but got Ok");
    }

    #[test]
    fn expr_to_name_truncates_utf8_safely() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create ctx");
        // Build a long expression comprised of multibyte chars to exceed 96 chars
        let mut chain: Vec<String> = Vec::new();
        for _ in 0..50 {
            // each "错误" is 6 bytes, 2 chars -> quickly exceeds 96 chars
            chain.push("错误".to_string());
        }
        let expr = crate::script::Expr::ChainAccess(chain);
        let s = ctx.expr_to_name(&expr);
        // Ensure we got a trailing ellipsis and no panic on multibyte boundary
        assert!(s.ends_with("..."));
        assert!(s.chars().count() <= 96);
    }

    #[test]
    fn pointer_int_arithmetic_is_rejected_with_friendly_error() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx = EbpfContext::new(&context, "ptr_arith", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");

        // Create a script variable 'p' of pointer type (null pointer)
        let ptr_ty = ctx.context.ptr_type(inkwell::AddressSpace::default());
        let null_ptr = ptr_ty.const_null();
        ctx.store_variable("p", null_ptr.into()).expect("store ptr");

        // Expression: p + 1
        let expr = crate::script::Expr::BinaryOp {
            left: Box::new(crate::script::Expr::Variable("p".to_string())),
            op: crate::script::BinaryOp::Add,
            right: Box::new(crate::script::Expr::Int(1)),
        };
        let res = ctx.compile_expr(&expr);
        assert!(res.is_err(), "expected pointer-int arithmetic error");
        let msg = format!("{:?}", res.err());
        assert!(
            msg.contains("pointer and integer")
                || msg.contains("Unsupported operation between pointer and integer"),
            "unexpected error message: {msg}"
        );
    }
}

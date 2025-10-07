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
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
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
            // 1) Script variables first
            E::Variable(name) if self.variable_exists(name) => {
                let val = self.load_variable(name)?;
                let var_name_index = self.trace_context.add_variable_name(name.clone());
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
                        // Treat as pointer value (rendered as hex). Cast to i64 payload.
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
                    .ok_or_else(|| CodeGenError::VariableNotFound(format!("{:?}", inner)))?;
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
                    .ok_or_else(|| CodeGenError::VariableNotFound(format!("{:?}", expr)))?;
                let dwarf_type = var.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
                })?;
                let mut data_len = Self::compute_read_size_for_type(dwarf_type);
                if data_len == 0 {
                    return Err(CodeGenError::TypeSizeNotAvailable(var.name));
                }
                data_len = std::cmp::min(data_len, 1993);
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
                                    let mut data_len = Self::compute_read_size_for_type(t);
                                    if data_len == 0 {
                                        return Err(CodeGenError::TypeSizeNotAvailable(v.name));
                                    }
                                    data_len = std::cmp::min(data_len, 1993);
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
                            let mut data_len = Self::compute_read_size_for_type(t);
                            if data_len == 0 {
                                return Err(CodeGenError::TypeSizeNotAvailable(v.name));
                            }
                            data_len = std::cmp::min(data_len, 1993);
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
                    Err(CodeGenError::VariableNotFound(name.clone()))
                }
            }

            // 7) Binary and other rvalue expressions → compile to computed int
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

        // Create instruction buffer
        let inst_buffer = self.create_instruction_buffer();

        // Write InstructionHeader.inst_type
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        self.builder
            .build_store(
                data_length_ptr_cast,
                self.context
                    .i16_type()
                    .const_int(total_data_length as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

        // Data pointer (after header)
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(header_size as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {}", e)))?
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
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {}", e))
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
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {}", e))
            })?;
        self.builder
            .build_store(var_name_index_ptr_i16, var_name_index_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store var_name_index: {}", e))
            })?;

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
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {}", e))
                })?
        };
        let type_index_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {}", e))
            })?;
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {}", e))
                })?
        };
        self.builder
            .build_store(access_path_len_ptr, self.context.i8_type().const_zero())
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {}", e))
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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e)))?
        };
        self.builder
            .build_store(status_ptr, self.context.i8_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

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
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_len GEP: {}", e))
                })?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {}", e)))?;
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(byte_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;

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
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_data GEP: {}", e))
                })?
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

        // Send via ringbuf
        self.send_instruction_via_ringbuf(
            inst_buffer,
            self.context.i64_type().const_int(total_size as u64, false),
        )?;

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
                E::String(s) => format!("\"{}\"", s),
                E::Float(v) => format!("{}", v),
                E::Bool(v) => v.to_string(),
                E::SpecialVar(s) => format!("${}", s),
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
        let mut s = inner(expr);
        const MAX_NAME: usize = 96;
        if s.len() > MAX_NAME {
            s.truncate(MAX_NAME.saturating_sub(3));
            s.push_str("...");
        }
        s
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
            Statement::VarDeclaration { name, value } => {
                info!("Processing variable declaration: {} = {:?}", name, value);
                // Compile the value expression and store in variable
                let compiled_value = self.compile_expr(value)?;
                self.store_variable(name, compiled_value)?;
                Ok(0) // VarDeclaration doesn't generate instructions
            }
            Statement::Print(print_stmt) => self.compile_print_statement(print_stmt),
            Statement::If {
                condition,
                then_body,
                else_body,
            } => {
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
                                CodeGenError::LLVMError(format!(
                                    "Failed to create condition: {}",
                                    e
                                ))
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

                // Create basic blocks for then and else paths
                let then_block = self
                    .context
                    .append_basic_block(current_function, "then_block");
                let else_block = self
                    .context
                    .append_basic_block(current_function, "else_block");
                let merge_block = self
                    .context
                    .append_basic_block(current_function, "merge_block");

                // Branch based on condition
                self.builder
                    .build_conditional_branch(cond_bool, then_block, else_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to create branch: {}", e))
                    })?;

                // Build then block
                self.builder.position_at_end(then_block);
                let mut then_instructions = 0u16;
                for stmt in then_body {
                    then_instructions += self.compile_statement(stmt)?;
                }
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {}", e))
                    })?;

                // Build else block
                self.builder.position_at_end(else_block);
                let mut else_instructions = 0u16;
                if let Some(else_stmt) = else_body {
                    else_instructions += self.compile_statement(else_stmt)?;
                }
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {}", e))
                    })?;

                // Continue with merge block
                self.builder.position_at_end(merge_block);

                // Return the maximum instructions from either branch
                Ok(std::cmp::max(then_instructions, else_instructions))
            }
            Statement::Block(nested_statements) => {
                let mut total_instructions = 0u16;
                for stmt in nested_statements {
                    total_instructions += self.compile_statement(stmt)?;
                }
                Ok(total_instructions)
            }
            Statement::TracePoint { pattern: _, body } => {
                let mut total_instructions = 0u16;
                for stmt in body {
                    total_instructions += self.compile_statement(stmt)?;
                }
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
        for a in args.iter() {
            complex_args.push(self.resolve_expr_to_arg(a)?);
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

        // Calculate total size (reserve worst-case payload per-arg to avoid overflow)
        let mut total_args_payload = 0usize;
        let mut arg_count = 0u8;
        for a in complex_args.iter() {
            // Header bytes per-arg: var_name_index(2) + type_index(2) + status(1) + access_path_len(1) + access_path + data_len(2)
            let header_len = 2 + 2 + 1 + 1 + a.access_path.len() + 2;
            // Reserve payload bytes: for runtime reads, failures may carry errno(4)+addr(8) = 12 bytes
            let reserved_payload = match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => bytes.len(),
                ComplexArgSource::AddressValue { .. } => 8,
                ComplexArgSource::RuntimeRead { .. } => std::cmp::max(a.data_len, 12),
                ComplexArgSource::ComputedInt { byte_len, .. } => *byte_len,
            };
            total_args_payload += header_len + reserved_payload;
            arg_count = arg_count.saturating_add(1);
        }
        let inst_data_size = std::mem::size_of::<PrintComplexFormatData>() + total_args_payload;
        let total_size = std::mem::size_of::<InstructionHeader>() + inst_data_size;

        // Allocate buffer
        let buffer = self.create_instruction_buffer();

        // Avoid memset; global buffer is zero-initialized

        // Write InstructionHeader
        let inst_type_val = self.context.i8_type().const_int(IT as u8 as u64, false);
        self.builder
            .build_store(buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;
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
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(inst_data_size as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get pcf_data_ptr GEP: {}", e))
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
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast fsi_ptr: {}", e)))?;
        let fsi_val = self
            .context
            .i16_type()
            .const_int(format_string_index as u64, false);
        self.builder
            .build_store(fsi_ptr, fsi_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store fsi: {}", e)))?;
        // arg_count (u8) at +2
        let arg_cnt_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(2, false)],
                    "arg_count_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get arg_count GEP: {}", e))
                })?
        };
        self.builder
            .build_store(
                arg_cnt_ptr,
                self.context.i8_type().const_int(arg_count as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store arg_count: {}", e)))?;

        // Start of variable payload after PrintComplexFormatData — use compile-time offsets with reserved payload
        let mut offset = std::mem::size_of::<PrintComplexFormatData>();
        for a in complex_args.iter() {
            // Per-arg reserved payload length
            let reserved_len = match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => bytes.len(),
                ComplexArgSource::AddressValue { .. } => 8,
                ComplexArgSource::RuntimeRead { .. } => std::cmp::max(a.data_len, 12),
                ComplexArgSource::ComputedInt { byte_len, .. } => *byte_len,
            };

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
                        CodeGenError::LLVMError(format!("Failed to get arg_base GEP: {}", e))
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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast vni ptr: {}", e)))?;
            self.builder
                .build_store(
                    vni_cast,
                    self.context
                        .i16_type()
                        .const_int(a.var_name_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store vni: {}", e)))?;

            // type_index(u16) at +2
            let ti_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(2, false)],
                        "ti_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get ti GEP: {}", e)))?
            };
            let ti_cast = self
                .builder
                .build_pointer_cast(
                    ti_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "ti_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast ti ptr: {}", e)))?;
            self.builder
                .build_store(
                    ti_cast,
                    self.context
                        .i16_type()
                        .const_int(a.type_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store ti: {}", e)))?;

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
                        CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e))
                    })?
            };
            self.builder
                .build_store(apl_ptr, self.context.i8_type().const_int(0, false))
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

            // access_path_len(u8) at +4
            let apl_ptr2 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(4, false)],
                        "apl_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get apl GEP: {}", e)))?
            };
            self.builder
                .build_store(
                    apl_ptr2,
                    self.context
                        .i8_type()
                        .const_int(a.access_path.len() as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store apl: {}", e)))?;

            // access_path bytes at +6..+6+len
            for (i, b) in a.access_path.iter().enumerate() {
                let byte_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            arg_base,
                            &[self.context.i32_type().const_int((6 + i) as u64, false)],
                            &format!("ap_byte_{}", i),
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get ap byte GEP: {}", e))
                        })?
                };
                self.builder
                    .build_store(byte_ptr, self.context.i8_type().const_int(*b as u64, false))
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store ap byte: {}", e))
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
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get dl GEP: {}", e)))?
            };
            let dl_cast = self
                .builder
                .build_pointer_cast(
                    dl_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "dl_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast dl ptr: {}", e)))?;
            self.builder
                .build_store(
                    dl_cast,
                    self.context
                        .i16_type()
                        .const_int(reserved_len as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;

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
                        CodeGenError::LLVMError(format!("Failed to get var_data GEP: {}", e))
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
                                    &format!("var_byte_{}", i),
                                )
                                .map_err(|e| {
                                    CodeGenError::LLVMError(format!(
                                        "Failed to get var byte GEP: {}",
                                        e
                                    ))
                                })?
                        };
                        self.builder
                            .build_store(
                                byte_ptr,
                                self.context.i8_type().const_int(*b as u64, false),
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to store var byte: {}", e))
                            })?;
                    }
                    // data_len already set to reserved_len
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
                    let current_fn = self
                        .builder
                        .get_insert_block()
                        .unwrap()
                        .get_parent()
                        .unwrap();
                    let null_block = self.context.append_basic_block(current_fn, "null_deref");
                    let read_block = self.context.append_basic_block(current_fn, "read_user");
                    let cont2_block = self.context.append_basic_block(current_fn, "after_read");
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
                            CodeGenError::LLVMError(format!("Failed to cast errno ptr: {}", e))
                        })?;
                    self.builder.build_store(i32_ptr, ret).map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store errno: {}", e))
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
                                CodeGenError::LLVMError(format!("Failed to get addr gep: {}", e))
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
                            CodeGenError::LLVMError(format!("Failed to cast addr ptr: {}", e))
                        })?;
                    let src_as_i64 = src_addr;
                    self.builder
                        .build_store(addr_ptr, src_as_i64)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store addr: {}", e))
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

        // Send via ringbuf (reserved size is sufficient for worst-case payload)
        self.write_to_accumulation_buffer_or_send(buffer, total_size as u64)
            .map_err(|e| CodeGenError::LLVMError(format!("Ringbuf output failed: {}", e)))?;
        Ok(())
    }

    /// Generate eBPF code for PrintStringIndex instruction
    pub fn generate_print_string_index(&mut self, string_index: u16) -> Result<()> {
        info!(
            "Generating PrintStringIndex instruction: index={}",
            string_index
        );

        // Allocate instruction structure on eBPF stack
        let inst_buffer = self.create_instruction_buffer();

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
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get inst_type GEP: {}", e))
                })?
        };
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintStringIndex as u64, false);
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(std::mem::size_of::<PrintStringIndexData>() as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get string_index GEP: {}", e))
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
                CodeGenError::LLVMError(format!("Failed to cast string_index ptr: {}", e))
            })?;
        let string_index_val = self
            .context
            .i16_type()
            .const_int(string_index as u64, false);
        self.builder
            .build_store(string_index_i16_ptr, string_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store string_index: {}", e)))?;

        // Compute total instruction size: header + PrintStringIndexData
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<PrintStringIndexData>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>())
                as u64,
            false,
        );
        // Send via ringbuf
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)
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

        let inst_buffer = self.create_instruction_buffer();

        // Avoid memset; global buffer is zero-initialized

        // Store instruction type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintVariableIndex as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        let total_data_length = std::mem::size_of::<PrintVariableIndexData>() + data_size as usize;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(total_data_length as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get variable_data_start GEP: {}", e))
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
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {}", e))
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
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {}", e))
            })?;
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(var_name_index as u64, false);
        self.builder
            .build_store(var_name_index_i16_ptr, var_name_index_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store var_name_index: {}", e))
            })?;

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
                    CodeGenError::LLVMError(format!("Failed to get type_encoding GEP: {}", e))
                })?
        };
        let type_encoding_val = self
            .context
            .i8_type()
            .const_int(type_encoding as u8 as u64, false);
        self.builder
            .build_store(type_encoding_ptr, type_encoding_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store type_encoding: {}", e))
            })?;

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
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_len GEP: {}", e))
                })?
        };
        let data_len_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {}", e)))?;
        let data_len_val = self.context.i16_type().const_int(data_size as u64, false); // Store as u16
        self.builder
            .build_store(data_len_i16_ptr, data_len_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {}", e))
                })?
        };
        let type_index_i16_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {}", e))
            })?;
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        self.builder
            .build_store(type_index_i16_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {}", e)))?;

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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e)))?
        };
        let reserved_val = self
            .context
            .i8_type()
            .const_int(VariableStatus::Ok as u64, false);
        self.builder
            .build_store(reserved_ptr, reserved_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

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
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_data GEP: {}", e))
                })?
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
                            CodeGenError::LLVMError(format!("Failed to truncate to i8: {}", e))
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
                        CodeGenError::LLVMError(format!("Failed to store i8 data: {}", e))
                    })?;
            }
            2 => {
                // Store as i16
                let truncated = match var_data {
                    BasicValueEnum::IntValue(int_val) => self
                        .builder
                        .build_int_truncate(int_val, self.context.i16_type(), "truncated_i16")
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to truncate to i16: {}", e))
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
                        CodeGenError::LLVMError(format!("Failed to cast to i16 ptr: {}", e))
                    })?;
                self.builder.build_store(i16_ptr, truncated).map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to store i16 data: {}", e))
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
                                CodeGenError::LLVMError(format!("Failed to truncate to i32: {}", e))
                            })?;
                        let i32_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i32_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i32 ptr: {}", e))
                            })?;
                        self.builder.build_store(i32_ptr, truncated).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i32 data: {}", e))
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
                                CodeGenError::LLVMError(format!("Failed to cast to f32 ptr: {}", e))
                            })?;
                        self.builder.build_store(f32_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f32 data: {}", e))
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
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {}", e))
                            })?;
                        self.builder.build_store(i64_ptr, int_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i64 data: {}", e))
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
                                CodeGenError::LLVMError(format!("Failed to cast to f64 ptr: {}", e))
                            })?;
                        self.builder.build_store(f64_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f64 data: {}", e))
                        })?;
                    }
                    BasicValueEnum::PointerValue(ptr_val) => {
                        // Store pointer as u64
                        let ptr_int = self
                            .builder
                            .build_ptr_to_int(ptr_val, self.context.i64_type(), "ptr_as_int")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to convert ptr to int: {}",
                                    e
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
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {}", e))
                            })?;
                        self.builder.build_store(i64_ptr, ptr_int).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store pointer data: {}", e))
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
                    "Unsupported data size: {}",
                    data_size
                )));
            }
        }

        // Compute total instruction size: header + PrintVariableIndexData + payload
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<PrintVariableIndexData>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>()
                + data_size as usize) as u64,
            false,
        );
        // Send via ringbuf
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)
    }

    // PrintVariableError instruction has been removed; compile-time errors are returned as Err,
    // runtime errors are carried via per-variable status in Print* instructions.

    /// Generate Backtrace instruction
    pub fn generate_backtrace_instruction(&mut self, depth: u8) -> Result<()> {
        info!("Generating Backtrace instruction: depth={}", depth);

        let inst_buffer = self.create_instruction_buffer();

        // Avoid memset; global instruction buffer is zero-initialized
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<BacktraceData>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>())
                as u64,
            false,
        );

        // Send via ringbuf
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)
    }

    /// Send instruction via ringbuf using bpf_ringbuf_output
    fn send_instruction_via_ringbuf(
        &mut self,
        inst_ptr: PointerValue<'ctx>,
        inst_size: IntValue<'ctx>,
    ) -> Result<()> {
        info!("Sending instruction via ringbuf (size: {:?})", inst_size);

        // Convert IntValue to u64 for the ringbuf output call
        let size_value = inst_size.get_zero_extended_constant().ok_or_else(|| {
            CodeGenError::LLVMError("Failed to get instruction size as constant".to_string())
        })?;

        // Call the actual bpf_ringbuf_output helper function
        self.write_to_accumulation_buffer_or_send(inst_ptr, size_value)
            .map_err(|e| CodeGenError::LLVMError(format!("Ringbuf output failed: {}", e)))?;

        debug!("Successfully queued instruction for ringbuf output");
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
                        "Variable '{}' has no type information in DWARF",
                        var_name
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

    // removed legacy process_complex_variable_print — unified resolver path is used

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
        // Create instruction buffer
        let inst_buffer = self.create_instruction_buffer();

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

        // Avoid memset; global buffer is zero-initialized

        // Write InstructionHeader.inst_type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;
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
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        self.builder
            .build_store(
                data_length_ptr_cast,
                self.context
                    .i16_type()
                    .const_int(total_data_length as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;
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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {}", e)))?
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
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {}", e))
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
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {}", e))
            })?;
        self.builder
            .build_store(var_name_index_ptr_i16, var_name_index_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store var_name_index: {}", e))
            })?;
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
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {}", e))
                })?
        };
        let type_index_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {}", e))
            })?;
        let type_index_val = self
            .context
            .i16_type()
            .const_int(meta.type_index as u64, false);
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {}", e)))?;
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
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {}", e))
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
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {}", e))
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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e)))?
        };
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::Ok as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

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
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_len GEP: {}", e))
                })?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {}", e)))?;
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(data_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;
        tracing::trace!(
            data_len,
            "generate_print_complex_variable_runtime: wrote data_len"
        );

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
                    CodeGenError::LLVMError(format!("Failed to get access_path GEP: {}", e))
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
                        &format!("access_path_byte_{}", i),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!(
                            "Failed to get access_path byte GEP: {}",
                            e
                        ))
                    })?
            };
            let byte_val = self.context.i8_type().const_int(byte as u64, false);
            self.builder.build_store(byte_ptr, byte_val).map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path byte: {}", e))
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
                    CodeGenError::LLVMError(format!("Failed to get variable_data GEP: {}", e))
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

        // Branch: NULL deref if src_addr == 0
        let zero64 = i64_type.const_zero();
        let is_null = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, src_addr, zero64, "is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let current_fn = self
            .builder
            .get_insert_block()
            .unwrap()
            .get_parent()
            .unwrap();
        let null_block = self.context.append_basic_block(current_fn, "null_deref");
        let read_block = self.context.append_basic_block(current_fn, "read_user");
        let cont_block = self.context.append_basic_block(current_fn, "after_read");
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
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast errno ptr: {}", e)))?;
        self.builder
            .build_store(errno_ptr, ret)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store errno: {}", e)))?;
        // write addr at [4..12]
        let addr_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_ptr,
                    &[self.context.i32_type().const_int(4, false)],
                    "addr_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get addr GEP: {}", e)))?
        };
        let addr_ptr = self
            .builder
            .build_pointer_cast(
                addr_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "addr_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast addr ptr: {}", e)))?;
        self.builder
            .build_store(addr_ptr, src_addr)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store addr: {}", e)))?;
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

        // Send the instruction via ringbuf
        self.send_instruction_via_ringbuf(
            inst_buffer,
            self.context.i64_type().const_int(total_size as u64, false),
        )?;
        tracing::trace!(
            total_size,
            "generate_print_complex_variable_runtime: sent via ringbuf"
        );

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
}

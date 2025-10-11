//! Expression compilation for eBPF code generation
//!
//! This module handles compilation of various expression types to LLVM IR.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::{BinaryOp, Expr};
use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user;
use ghostscope_dwarf::TypeInfo as DwarfType;
use inkwell::values::BasicValueEnum;
use inkwell::AddressSpace;
use tracing::debug;

// compare cap is provided via compile_options.compare_cap (config: ebpf.compare_cap)

impl<'ctx> EbpfContext<'ctx> {
    /// Ensure that when an expression refers to a DWARF-backed variable (not via address-of),
    /// the variable's DWARF type is a pointer or array (decays to pointer for memcmp/strncmp).
    fn ensure_dwarf_pointer_arg(&mut self, e: &Expr, where_ctx: &str) -> Result<()> {
        // Allow explicit address-of forms (&expr), which purposefully produce a pointer
        if matches!(e, Expr::AddressOf(_)) {
            return Ok(());
        }
        match self.query_dwarf_for_complex_expr(e) {
            Ok(Some(var)) => {
                let Some(mut ty) = var.dwarf_type.as_ref() else {
                    return Err(CodeGenError::TypeError(format!(
                        "{where_ctx}: DWARF variable has no type information"
                    )));
                };
                // Unwrap typedef/qualified wrappers
                loop {
                    match ty {
                        DwarfType::TypedefType {
                            underlying_type, ..
                        } => ty = underlying_type.as_ref(),
                        DwarfType::QualifiedType {
                            underlying_type, ..
                        } => ty = underlying_type.as_ref(),
                        _ => break,
                    }
                }
                if !matches!(
                    ty,
                    DwarfType::PointerType { .. } | DwarfType::ArrayType { .. }
                ) {
                    return Err(CodeGenError::TypeError(format!(
                        "{where_ctx}: only pointer or array DWARF variables are supported"
                    )));
                }
                Ok(())
            }
            // No DWARF info or analyzer missing: allow script-level pointer values
            Ok(None) | Err(_) => match self.compile_expr(e) {
                Ok(BasicValueEnum::PointerValue(_)) => Ok(()),
                _ => Err(CodeGenError::TypeError(format!(
                    "{where_ctx}: expression is not a pointer"
                ))),
            },
        }
    }

    /// Resolve an expression to an i64 pointer value. Accepts integer (address) and pointer values;
    /// falls back to DWARF evaluation for complex expressions.
    pub(crate) fn resolve_ptr_i64_from_expr(
        &mut self,
        e: &Expr,
    ) -> Result<inkwell::values::IntValue<'ctx>> {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;
        use inkwell::values::BasicValueEnum::*;
        // Alias variable indirection: resolve its target expression first
        if let E::Variable(name) = e {
            if self.alias_variable_exists(name) {
                if let Some(target) = self.get_alias_variable(name) {
                    return self.resolve_ptr_i64_from_expr(&target);
                }
            }
        }
        // Special-case: explicit address-of must yield a pointer-sized address
        if let E::AddressOf(inner) = e {
            if let Some(var) = self.query_dwarf_for_complex_expr(inner)? {
                let module_hint = self.current_resolved_var_module_path.clone();
                let status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    None
                };
                return self.evaluation_result_to_address_with_hint(
                    &var.evaluation_result,
                    status_ptr,
                    module_hint.as_deref(),
                );
            } else {
                return Err(CodeGenError::TypeError(
                    "cannot take address of unresolved expression".into(),
                ));
            }
        }

        // Support constant-offset addressing: (alias_expr + K) or (K + alias_expr)
        if let E::BinaryOp { left, op, right } = e {
            if matches!(op, BO::Add) {
                let is_nonneg_lit = |x: &E| matches!(x, E::Int(v) if *v >= 0);
                // alias + K
                if is_nonneg_lit(right) {
                    if let Ok(base) = self.resolve_ptr_i64_from_expr(left) {
                        if let E::Int(k) = &**right {
                            let off = self.context.i64_type().const_int(*k as u64, false);
                            return self
                                .builder
                                .build_int_add(base, off, "ptr_add")
                                .map_err(|e| CodeGenError::Builder(e.to_string()));
                        }
                    }
                }
                // K + alias
                if is_nonneg_lit(left) {
                    if let Ok(base) = self.resolve_ptr_i64_from_expr(right) {
                        if let E::Int(k) = &**left {
                            let off = self.context.i64_type().const_int(*k as u64, false);
                            return self
                                .builder
                                .build_int_add(base, off, "ptr_add")
                                .map_err(|e| CodeGenError::Builder(e.to_string()));
                        }
                    }
                }
            }
        }
        // Prefer DWARF-based address resolution first so that array/aggregate
        // expressions decay to their base address rather than loading values.
        if let Ok(Some(var)) = self.query_dwarf_for_complex_expr(e) {
            if let Some(mut dty) = var.dwarf_type.as_ref() {
                // unwrap aliases
                loop {
                    match dty {
                        DwarfType::TypedefType {
                            underlying_type, ..
                        } => dty = underlying_type.as_ref(),
                        DwarfType::QualifiedType {
                            underlying_type, ..
                        } => dty = underlying_type.as_ref(),
                        _ => break,
                    }
                }
                match dty {
                    DwarfType::PointerType { .. } => {
                        let val_any = self.evaluate_result_to_llvm_value(
                            &var.evaluation_result,
                            dty,
                            &var.name,
                            self.get_compile_time_context()?.pc_address,
                        )?;
                        match val_any {
                            IntValue(iv) => Ok(iv),
                            PointerValue(pv) => self
                                .builder
                                .build_ptr_to_int(pv, self.context.i64_type(), "ptr_as_i64")
                                .map_err(|e| CodeGenError::Builder(e.to_string())),
                            _ => Err(CodeGenError::TypeError(
                                "DWARF value is not pointer/integer".into(),
                            )),
                        }
                    }
                    DwarfType::ArrayType { .. } => {
                        // Use the base address of the array as pointer
                        let module_hint = self.current_resolved_var_module_path.clone();
                        let status_ptr = if self.condition_context_active {
                            Some(self.get_or_create_cond_error_global())
                        } else {
                            None
                        };
                        self.evaluation_result_to_address_with_hint(
                            &var.evaluation_result,
                            status_ptr,
                            module_hint.as_deref(),
                        )
                    }
                    _ => Err(CodeGenError::TypeError(
                        "DWARF value is not pointer/array".into(),
                    )),
                }
            } else {
                let module_hint = self.current_resolved_var_module_path.clone();
                let status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    None
                };
                self.evaluation_result_to_address_with_hint(
                    &var.evaluation_result,
                    status_ptr,
                    module_hint.as_deref(),
                )
            }
        } else {
            // No DWARF-backed address and not an address-of/alias+const: reject script-level pointers.
            Err(CodeGenError::TypeError(
                "expression is not a pointer/address".into(),
            ))
        }
    }
    /// Builtin memcmp (boolean variant): returns true iff first `len` bytes equal.
    /// Supports dynamic `len` (expr), clamped to [0, compare_cap].
    fn compile_memcmp_builtin(
        &mut self,
        a_expr: &Expr,
        b_expr: &Expr,
        len_expr: &Expr,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Note: constant hex/len validation happens at parse-time; dynamic cases are handled at runtime by masking bytes.
        // Important: Clear register cache to avoid reusing register values
        // loaded in a previous basic block, which can violate SSA dominance
        // when multiple memcmp calls appear in one function.
        self.register_cache.clear();

        // Note: do not resolve pointers yet; if either side is hex("...") we will synthesize bytes

        // Compile length expr to i32 and clamp to [0, CAP]
        let len_val = self.compile_expr(len_expr)?;
        let len_iv = match len_val {
            BasicValueEnum::IntValue(iv) => iv,
            _ => {
                return Err(CodeGenError::TypeError(
                    "memcmp length must be an integer expression".into(),
                ))
            }
        };
        let i32_ty = self.context.i32_type();
        let len_i32 = if len_iv.get_type().get_bit_width() > 32 {
            self.builder
                .build_int_truncate(len_iv, i32_ty, "memcmp_len_trunc")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        } else if len_iv.get_type().get_bit_width() < 32 {
            self.builder
                .build_int_z_extend(len_iv, i32_ty, "memcmp_len_zext")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        } else {
            len_iv
        };
        let zero_i32 = i32_ty.const_zero();
        let is_neg = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::SLT,
                len_i32,
                zero_i32,
                "memcmp_len_neg",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let len_nn = self
            .builder
            .build_select(is_neg, zero_i32, len_i32, "memcmp_len_nn")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let cap = self.compile_options.compare_cap;
        let cap_const = i32_ty.const_int(cap as u64, false);
        let gt = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                len_nn,
                cap_const,
                "memcmp_len_gt",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let sel_len = self
            .builder
            .build_select(gt, cap_const, len_nn, "memcmp_len_sel")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        // Fast-path: if effective length is zero, return true without any reads
        let len_is_zero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                sel_len,
                i32_ty.const_zero(),
                "memcmp_len_is_zero",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let curr_block = self.builder.get_insert_block().unwrap();
        let func = curr_block.get_parent().unwrap();
        let zero_b = self.context.append_basic_block(func, "memcmp_len_zero");
        let nz_b = self.context.append_basic_block(func, "memcmp_len_nz");
        let cont_b = self.context.append_basic_block(func, "memcmp_len_cont");
        self.builder
            .build_conditional_branch(len_is_zero, zero_b, nz_b)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Zero-length branch: true
        self.builder.position_at_end(zero_b);
        let bool_true = self.context.bool_type().const_int(1, false);
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let zero_block = self.builder.get_insert_block().unwrap();

        // Non-zero branch: perform reads and compare
        self.builder.position_at_end(nz_b);

        // Prepare static buffers of size CAP for both sides
        let (arr_a_ty, buf_a) = self.get_or_create_i8_buffer(cap, "_gs_bi_memcmp_a");
        let (arr_b_ty, buf_b) = self.get_or_create_i8_buffer(cap, "_gs_bi_memcmp_b");
        let ptr_ty = self.context.ptr_type(AddressSpace::default());

        // Helper: parse hex builtin into bytes
        let parse_hex_bytes = |e: &Expr| -> Option<Vec<u8>> {
            if let Expr::BuiltinCall { name, args } = e {
                if name == "hex" && args.len() == 1 {
                    if let Expr::String(s) = &args[0] {
                        // Parser guarantees only hex digits and even length
                        if s.is_empty() {
                            return Some(Vec::new());
                        }
                        let mut out = Vec::with_capacity(s.len() / 2);
                        let mut i = 0usize;
                        while i + 1 < s.len() {
                            let v = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
                            out.push(v);
                            i += 2;
                        }
                        return Some(out);
                    }
                }
            }
            None
        };

        // Side A
        // If side A is DWARF-backed (and not an explicit address-of), enforce pointer DWARF type
        if parse_hex_bytes(a_expr).is_none() {
            self.ensure_dwarf_pointer_arg(a_expr, "memcmp arg0")?;
        }
        let ok_a = if let Some(bytes) = parse_hex_bytes(a_expr) {
            let i32_ty = self.context.i32_type();
            let idx0 = i32_ty.const_zero();
            for i in 0..(cap as usize) {
                let idx_i = i32_ty.const_int(i as u64, false);
                let pa = unsafe {
                    self.builder
                        .build_gep(arr_a_ty, buf_a, &[idx0, idx_i], &format!("hex_a_i{i}"))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                };
                let byte = if i < bytes.len() { bytes[i] } else { 0 } as u64;
                let bv = self.context.i8_type().const_int(byte, false);
                self.builder
                    .build_store(pa, bv)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            }
            self.context.bool_type().const_int(1, false)
        } else {
            // Resolve pointer for A and read from user memory
            let ptr_a = self.resolve_ptr_i64_from_expr(a_expr)?;
            let dst_a = self
                .builder
                .build_bit_cast(buf_a, ptr_ty, "memcmp_dst_a")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let src_a = self
                .builder
                .build_int_to_ptr(ptr_a, ptr_ty, "memcmp_src_a")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let ret_a = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[dst_a, sel_len.into(), src_a.into()],
                    self.context.i64_type().into(),
                    "probe_read_user_memcmp_a",
                )?
                .into_int_value();
            let i64_ty = self.context.i64_type();
            self.builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    ret_a,
                    i64_ty.const_zero(),
                    "memcmp_ok_a",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        // Side B
        if parse_hex_bytes(b_expr).is_none() {
            self.ensure_dwarf_pointer_arg(b_expr, "memcmp arg1")?;
        }
        let ok_b = if let Some(bytes) = parse_hex_bytes(b_expr) {
            let i32_ty = self.context.i32_type();
            let idx0 = i32_ty.const_zero();
            for i in 0..(cap as usize) {
                let idx_i = i32_ty.const_int(i as u64, false);
                let pb = unsafe {
                    self.builder
                        .build_gep(arr_b_ty, buf_b, &[idx0, idx_i], &format!("hex_b_i{i}"))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                };
                let byte = if i < bytes.len() { bytes[i] } else { 0 } as u64;
                let bv = self.context.i8_type().const_int(byte, false);
                self.builder
                    .build_store(pb, bv)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            }
            self.context.bool_type().const_int(1, false)
        } else {
            // Resolve pointer for B and read from user memory
            let ptr_b = self.resolve_ptr_i64_from_expr(b_expr)?;
            let dst_b = self
                .builder
                .build_bit_cast(buf_b, ptr_ty, "memcmp_dst_b")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let src_b = self
                .builder
                .build_int_to_ptr(ptr_b, ptr_ty, "memcmp_src_b")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let ret_b = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[dst_b, sel_len.into(), src_b.into()],
                    self.context.i64_type().into(),
                    "probe_read_user_memcmp_b",
                )?
                .into_int_value();
            let i64_ty = self.context.i64_type();
            self.builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    ret_b,
                    i64_ty.const_zero(),
                    "memcmp_ok_b",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        let status_ok = self
            .builder
            .build_and(ok_a, ok_b, "memcmp_status_ok")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // If in condition context and either side failed, set condition error code = 1 (ProbeReadFailed)
        if self.condition_context_active {
            let not_a = self
                .builder
                .build_not(ok_a, "memcmp_fail_a")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let not_b = self
                .builder
                .build_not(ok_b, "memcmp_fail_b")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let any_fail = self
                .builder
                .build_or(not_a, not_b, "memcmp_any_fail")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let cur_block = self.builder.get_insert_block().unwrap();
            let func = cur_block.get_parent().unwrap();
            let set_b = self.context.append_basic_block(func, "memcmp_set_err");
            let cont_b = self.context.append_basic_block(func, "memcmp_cont");
            self.builder
                .build_conditional_branch(any_fail, set_b, cont_b)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(set_b);
            // Align error_code with VariableStatus::ReadError = 2
            let _ = self.set_condition_error_if_unset(2u8);
            // Decide which side failed (prefer recording the actual failing side)
            let not_a_val = self
                .builder
                .build_not(ok_a, "memcmp_fail_a_val")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let not_b_val = self
                .builder
                .build_not(ok_b, "memcmp_fail_b_val")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let cur_fn = self
                .builder
                .get_insert_block()
                .unwrap()
                .get_parent()
                .unwrap();
            let set_a_bb = self.context.append_basic_block(cur_fn, "set_addr_a");
            let check_b_bb = self.context.append_basic_block(cur_fn, "check_fail_b");
            let set_b_bb = self.context.append_basic_block(cur_fn, "set_addr_b");
            let after_set_bb = self.context.append_basic_block(cur_fn, "after_set_addr");

            // Branch on A failure first
            self.builder
                .build_conditional_branch(not_a_val, set_a_bb, check_b_bb)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // set A address
            self.builder.position_at_end(set_a_bb);
            if let Some(pa) = match parse_hex_bytes(a_expr) {
                Some(_) => None,
                None => Some(self.resolve_ptr_i64_from_expr(a_expr)?),
            } {
                let _ = self.set_condition_error_addr_if_unset(pa);
            }
            self.builder
                .build_unconditional_branch(after_set_bb)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // check B failure and set B
            self.builder.position_at_end(check_b_bb);
            self.builder
                .build_conditional_branch(not_b_val, set_b_bb, after_set_bb)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(set_b_bb);
            if let Some(pb) = match parse_hex_bytes(b_expr) {
                Some(_) => None,
                None => Some(self.resolve_ptr_i64_from_expr(b_expr)?),
            } {
                let _ = self.set_condition_error_addr_if_unset(pb);
            }
            self.builder
                .build_unconditional_branch(after_set_bb)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(after_set_bb);
            // Build flags: bit0=A fail, bit1=B fail, bit2=len clamped, bit3=len<=0
            let i8t = self.context.i8_type();
            let b_a = self
                .builder
                .build_int_z_extend(
                    self.builder
                        .build_not(ok_a, "fa")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    i8t,
                    "fa8",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let b_b1 = self
                .builder
                .build_int_z_extend(
                    self.builder
                        .build_not(ok_b, "fb")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    i8t,
                    "fb8",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let sh1 = self
                .builder
                .build_left_shift(b_b1, i8t.const_int(1, false), "b_b_shift")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            // gt: len_nn > cap  (len clamped)
            let b_c = self
                .builder
                .build_int_z_extend(gt, i8t, "clamped8")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let sh2 = self
                .builder
                .build_left_shift(b_c, i8t.const_int(2, false), "b_c_shift")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            // len<=0: reuse len_is_zero
            let b_z = self
                .builder
                .build_int_z_extend(len_is_zero, i8t, "len0_8")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let sh3 = self
                .builder
                .build_left_shift(b_z, i8t.const_int(3, false), "b_z_shift")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let f01 = self
                .builder
                .build_or(b_a, sh1, "f01")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let f012 = self
                .builder
                .build_or(f01, sh2, "f012")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let flags = self
                .builder
                .build_or(f012, sh3, "flags")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let _ = self.or_condition_error_flags(flags);
            self.builder
                .build_unconditional_branch(cont_b)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(cont_b);
        }

        // Aggregate XOR/OR across 0..CAP, masked by (i < sel_len)
        let i32_ty = self.context.i32_type();
        let idx0 = i32_ty.const_zero();
        let mut acc = self.context.i8_type().const_zero();
        for i in 0..cap as usize {
            let idx_i = i32_ty.const_int(i as u64, false);
            // active = (i < sel_len)
            let active = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    idx_i,
                    sel_len,
                    &format!("memcmp_i{i}_active"),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            // a[i]
            let pa = unsafe {
                self.builder
                    .build_gep(arr_a_ty, buf_a, &[idx0, idx_i], &format!("memcmp_a_i{i}"))
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let va = self
                .builder
                .build_load(self.context.i8_type(), pa, &format!("ld_a_{i}"))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let va = match va {
                BasicValueEnum::IntValue(iv) => iv,
                _ => return Err(CodeGenError::LLVMError("memcmp load a != i8".into())),
            };
            // b[i]
            let pb = unsafe {
                self.builder
                    .build_gep(arr_b_ty, buf_b, &[idx0, idx_i], &format!("memcmp_b_i{i}"))
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let vb = self
                .builder
                .build_load(self.context.i8_type(), pb, &format!("ld_b_{i}"))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let vb = match vb {
                BasicValueEnum::IntValue(iv) => iv,
                _ => return Err(CodeGenError::LLVMError("memcmp load b != i8".into())),
            };
            let diff = self
                .builder
                .build_xor(va, vb, &format!("memcmp_diff_{i}"))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let zero8 = self.context.i8_type().const_zero();
            let masked = self
                .builder
                .build_select(active, diff, zero8, &format!("memcmp_masked_{i}"))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                .into_int_value();
            acc = self
                .builder
                .build_or(acc, masked, &format!("memcmp_acc_{i}"))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }
        let eq_bytes = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                acc,
                self.context.i8_type().const_zero(),
                "memcmp_acc_zero",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let nz_result = self
            .builder
            .build_and(status_ok, eq_bytes, "memcmp_and")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let nz_block = self.builder.get_insert_block().unwrap();

        // Merge
        self.builder.position_at_end(cont_b);
        let phi = self
            .builder
            .build_phi(self.context.bool_type(), "memcmp_phi")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        phi.add_incoming(&[(&bool_true, zero_block), (&nz_result, nz_block)]);
        Ok(phi.as_basic_value())
    }
    /// Builtin strncmp/starts_with implementation: bounded byte-compare without NUL requirement.
    fn compile_strncmp_builtin(
        &mut self,
        dwarf_expr: &Expr,
        lit: &str,
        n: u32,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Fast path: if the first argument is a script string variable or a string literal,
        // perform a compile-time bounded comparison and return a constant boolean.
        let immediate_bytes_opt = match dwarf_expr {
            Expr::Variable(name) => {
                if self
                    .get_variable_type(name)
                    .is_some_and(|t| matches!(t, crate::script::VarType::String))
                {
                    self.get_string_variable_bytes(name).cloned()
                } else {
                    None
                }
            }
            Expr::String(s) => {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                Some(b)
            }
            _ => None,
        };

        if let Some(bytes) = immediate_bytes_opt {
            // Treat as bounded byte compare between two immediate strings
            let lit_bytes = lit.as_bytes();
            let cap = self.compile_options.compare_cap as usize;
            let n_usize = std::cmp::min(n as usize, cap);
            // compute source content length up to NUL
            let content_len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            let cmp_len = std::cmp::min(n_usize, std::cmp::min(content_len, lit_bytes.len()));
            let equal =
                bytes.get(0..cmp_len).unwrap_or(&[]) == lit_bytes.get(0..cmp_len).unwrap_or(&[]);
            let bool_val = self
                .context
                .bool_type()
                .const_int(if equal { 1 } else { 0 }, false);
            return Ok(bool_val.into());
        }

        // Determine pointer value (i64) of the target memory (DWARF or alias)
        // Prefer DWARF resolution for richer status/hints; fallback to generic pointer resolver.
        let ptr_i64 = match self.query_dwarf_for_complex_expr(dwarf_expr)? {
            Some(var) => {
                if let Some(mut ty) = var.dwarf_type.as_ref() {
                    loop {
                        match ty {
                            DwarfType::TypedefType {
                                underlying_type, ..
                            } => ty = underlying_type.as_ref(),
                            DwarfType::QualifiedType {
                                underlying_type, ..
                            } => ty = underlying_type.as_ref(),
                            _ => break,
                        }
                    }
                    match ty {
                        DwarfType::PointerType { .. } => {
                            let val_any = self.evaluate_result_to_llvm_value(
                                &var.evaluation_result,
                                ty,
                                &var.name,
                                self.get_compile_time_context()?.pc_address,
                            )?;
                            match val_any {
                                BasicValueEnum::IntValue(iv) => iv,
                                BasicValueEnum::PointerValue(pv) => self
                                    .builder
                                    .build_ptr_to_int(pv, self.context.i64_type(), "ptr_as_i64")
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                                _ => {
                                    return Err(CodeGenError::TypeError(
                                        "strncmp requires pointer/integer value for pointer; got unsupported DWARF value".into(),
                                    ))
                                }
                            }
                        }
                        DwarfType::ArrayType { .. } => {
                            let module_hint = self.current_resolved_var_module_path.clone();
                            let status_ptr = if self.condition_context_active {
                                Some(self.get_or_create_cond_error_global())
                            } else {
                                None
                            };
                            self.evaluation_result_to_address_with_hint(
                                &var.evaluation_result,
                                status_ptr,
                                module_hint.as_deref(),
                            )?
                        }
                        _ => {
                            // Not a pointer/array -> treat as error
                            return Err(CodeGenError::TypeError(
                                "strncmp requires the non-string side to be an address expression (pointer/array)".into(),
                            ));
                        }
                    }
                } else {
                    return Err(CodeGenError::TypeError(
                        "strncmp non-string side lacks DWARF type info".into(),
                    ));
                }
            }
            None => {
                // Generic pointer expr (e.g., alias); resolve to i64
                self.resolve_ptr_i64_from_expr(dwarf_expr).map_err(|_| {
                    CodeGenError::TypeError(
                        "strncmp requires at least one string argument, and the other side must be an address expression (DWARF pointer/array or alias)".to_string(),
                    )
                })?
            }
        };

        // Cap read length for safety
        let cap = self.compile_options.compare_cap;
        let max_n = std::cmp::min(n, cap);
        let lit_len = std::cmp::min(lit.len() as u32, cap);
        let cmp_len = std::cmp::min(max_n, lit_len);

        // Read bytes into buffer
        let (buf_global, status, arr_ty) =
            self.read_user_bytes_into_buffer(ptr_i64, cmp_len, "_gs_bi_strncmp")?;
        let status_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                status,
                self.context.i64_type().const_zero(),
                "rd_ok",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // If in condition context and read failed, set condition error code = 1 (ProbeReadFailed)
        if self.condition_context_active {
            let cur_block = self.builder.get_insert_block().unwrap();
            let func = cur_block.get_parent().unwrap();
            let set_b = self.context.append_basic_block(func, "strncmp_set_err");
            let cont_b = self.context.append_basic_block(func, "strncmp_cont");
            let not_ok = self
                .builder
                .build_not(status_ok, "rd_fail")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder
                .build_conditional_branch(not_ok, set_b, cont_b)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(set_b);
            // VariableStatus::ReadError = 2
            let _ = self.set_condition_error_if_unset(2u8);
            let _ = self.set_condition_error_addr_if_unset(ptr_i64);
            // flags: bit0 = read failure for strncmp
            let one = self.context.i8_type().const_int(1, false);
            let _ = self.or_condition_error_flags(one);
            self.builder
                .build_unconditional_branch(cont_b)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(cont_b);
        }

        // XOR/OR accumulation over cmp_len bytes
        let i32_ty = self.context.i32_type();
        let idx0 = i32_ty.const_zero();
        let mut acc = self.context.i8_type().const_zero();
        for (i, b) in lit.as_bytes().iter().take(cmp_len as usize).enumerate() {
            let idx_i = i32_ty.const_int(i as u64, false);
            let ptr_i = unsafe {
                self.builder
                    .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let ch = self
                .builder
                .build_load(self.context.i8_type(), ptr_i, "ch")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let ch = match ch {
                BasicValueEnum::IntValue(iv) => iv,
                _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
            };
            let expect = self.context.i8_type().const_int(*b as u64, false);
            let diff = self
                .builder
                .build_xor(ch, expect, "diff")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            acc = self
                .builder
                .build_or(acc, diff, "acc_or")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }
        let eq_bytes = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                acc,
                self.context.i8_type().const_zero(),
                "acc_zero",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let result = self
            .builder
            .build_and(status_ok, eq_bytes, "strncmp_and")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        Ok(result.into())
    }
    /// Compile an expression
    pub fn compile_expr(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>> {
        match expr {
            Expr::Int(value) => {
                // Treat script integer literals as signed i64 constants
                let int_value = self.context.i64_type().const_int(*value as u64, true);
                debug!(
                    "compile_expr: Int literal {} compiled to IntValue with bit width {}",
                    value,
                    int_value.get_type().get_bit_width()
                );
                Ok(int_value.into())
            }
            Expr::Float(_value) => Err(CodeGenError::TypeError(
                "Floating point expressions are not supported".to_string(),
            )),
            Expr::String(value) => {
                // Create string constant using a simpler approach
                let string_value = self.context.const_string(value.as_bytes(), true);
                let global = self
                    .module
                    .add_global(string_value.get_type(), None, "str_const");
                global.set_initializer(&string_value);

                let ptr_type = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_bit_cast(global.as_pointer_value(), ptr_type, "str_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(cast_ptr)
            }
            Expr::Bool(value) => {
                // Represent booleans as i1 for logical/compare consistency
                let b = self
                    .context
                    .bool_type()
                    .const_int(if *value { 1 } else { 0 }, false);
                Ok(b.into())
            }
            Expr::UnaryNot(inner) => {
                // Compile operand to integer and compare EQ to zero to produce boolean not
                let v = self.compile_expr(inner)?;
                let iv = match v {
                    BasicValueEnum::IntValue(iv) => iv,
                    _ => {
                        return Err(CodeGenError::TypeError(
                            "Logical NOT requires integer/boolean operand".to_string(),
                        ))
                    }
                };
                let zero = iv.get_type().const_zero();
                let res = self
                    .builder
                    .build_int_compare(inkwell::IntPredicate::EQ, iv, zero, "not_eq0")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(res.into())
            }
            Expr::Variable(var_name) => {
                debug!("compile_expr: Compiling variable expression: {}", var_name);

                // First: DWARF alias variable takes precedence
                if self.alias_variable_exists(var_name) {
                    debug!(
                        "compile_expr: '{}' is an alias variable; resolving to runtime address",
                        var_name
                    );
                    let aliased = self
                        .get_alias_variable(var_name)
                        .expect("alias existence just checked");
                    // Resolve to i64 address then cast to ptr
                    let addr_i64 = self.resolve_ptr_i64_from_expr(&aliased)?;
                    let ptr_ty = self.context.ptr_type(AddressSpace::default());
                    let as_ptr = self
                        .builder
                        .build_int_to_ptr(addr_i64, ptr_ty, "alias_as_ptr")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    return Ok(as_ptr.into());
                }

                // Then check if it's a concrete script-defined variable
                if self.variable_exists(var_name) {
                    debug!("compile_expr: Found script variable: {}", var_name);
                    let loaded_value = self.load_variable(var_name)?;
                    debug!(
                        "compile_expr: Loaded variable '{}' with type: {:?}",
                        var_name,
                        loaded_value.get_type()
                    );
                    match &loaded_value {
                        BasicValueEnum::IntValue(iv) => debug!(
                            "compile_expr: Variable '{}' is IntValue with bit width {}",
                            var_name,
                            iv.get_type().get_bit_width()
                        ),
                        BasicValueEnum::FloatValue(_) => {
                            debug!("compile_expr: Variable '{}' is FloatValue", var_name)
                        }
                        BasicValueEnum::PointerValue(_) => {
                            debug!("compile_expr: Variable '{}' is PointerValue", var_name)
                        }
                        _ => debug!("compile_expr: Variable '{}' is other type", var_name),
                    }
                    return Ok(loaded_value);
                }

                // If not found in script variables nor alias map, try DWARF variables
                debug!(
                    "Variable '{}' not found in script variables, checking DWARF",
                    var_name
                );
                self.compile_dwarf_expression(expr)
            }
            Expr::SpecialVar(name) => {
                // Accept both "$pid" and "pid" forms from the parser
                let sanitized = name.trim_start_matches('$');
                self.handle_special_variable(sanitized)
            }
            Expr::BuiltinCall { name, args } => match name.as_str() {
                "memcmp" => {
                    if args.len() != 3 {
                        return Err(CodeGenError::TypeError("memcmp expects 3 arguments".into()));
                    }
                    self.compile_memcmp_builtin(&args[0], &args[1], &args[2])
                }
                "strncmp" => {
                    if args.len() != 3 {
                        return Err(CodeGenError::TypeError(
                            "strncmp expects 3 arguments".into(),
                        ));
                    }
                    let n = match &args[2] {
                        Expr::Int(v) if *v >= 0 => *v as u32,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "strncmp length must be a non-negative integer literal".into(),
                            ))
                        }
                    };
                    // Accept string on either side: string literal or script string variable
                    fn extract_script_string<'a>(
                        this: &mut EbpfContext<'a>,
                        e: &Expr,
                    ) -> Option<String> {
                        match e {
                            Expr::String(s) => Some(s.clone()),
                            Expr::Variable(name) => this
                                .get_variable_type(name)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String))
                                .then(|| {
                                    this.get_string_variable_bytes(name).map(|b| {
                                        let cut = b.iter().position(|&x| x == 0).unwrap_or(b.len());
                                        String::from_utf8_lossy(&b[..cut]).to_string()
                                    })
                                })
                                .flatten(),
                            _ => None,
                        }
                    }
                    let left_str = extract_script_string(self, &args[0]);
                    let right_str = extract_script_string(self, &args[1]);
                    match (left_str, right_str) {
                        (Some(ls), Some(rs)) => {
                            // Both sides strings -> compile-time fold
                            let ln = n as usize;
                            let eq = ls.as_bytes().iter().take(ln).eq(rs.as_bytes().iter().take(ln));
                            let bv = self.context.bool_type().const_int(eq as u64, false);
                            Ok(bv.into())
                        }
                        (Some(ls), None) => self.compile_strncmp_builtin(&args[1], &ls, n),
                        (None, Some(rs)) => self.compile_strncmp_builtin(&args[0], &rs, n),
                        (None, None) => Err(CodeGenError::TypeError(
                            "strncmp requires at least one string argument (string literal or script string variable) as the first or second parameter".into(),
                        )),
                    }
                }
                "starts_with" => {
                    if args.len() != 2 {
                        return Err(CodeGenError::TypeError(
                            "starts_with expects 2 arguments".into(),
                        ));
                    }
                    // Accept string on either side (literal or script string var)
                    fn extract_script_string<'a>(
                        this: &mut EbpfContext<'a>,
                        e: &Expr,
                    ) -> Option<String> {
                        match e {
                            Expr::String(s) => Some(s.clone()),
                            Expr::Variable(name) => this
                                .get_variable_type(name)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String))
                                .then(|| {
                                    this.get_string_variable_bytes(name).map(|b| {
                                        let cut = b.iter().position(|&x| x == 0).unwrap_or(b.len());
                                        String::from_utf8_lossy(&b[..cut]).to_string()
                                    })
                                })
                                .flatten(),
                            _ => None,
                        }
                    }
                    let s0 = extract_script_string(self, &args[0]);
                    let s1 = extract_script_string(self, &args[1]);
                    match (s0, s1) {
                        (Some(a), Some(b)) => {
                            // both strings -> compile-time fold
                            let ok = a.as_bytes().starts_with(b.as_bytes());
                            let bv = self.context.bool_type().const_int(ok as u64, false);
                            Ok(bv.into())
                        }
                        (Some(a), None) => self.compile_strncmp_builtin(&args[1], &a, a.len() as u32),
                        (None, Some(b)) => self.compile_strncmp_builtin(&args[0], &b, b.len() as u32),
                        (None, None) => Err(CodeGenError::TypeError(
                            "starts_with requires at least one string argument (string literal or script string variable) as the first or second parameter".into(),
                        )),
                    }
                }
                _ => Err(CodeGenError::NotImplemented(format!(
                    "Unknown builtin function: {name}"
                ))),
            },
            Expr::BinaryOp { left, op, right } => {
                // String comparison fast-path: script string vs DWARF char*/char[N]
                if matches!(op, BinaryOp::Equal | BinaryOp::NotEqual) {
                    if let (Expr::String(lit), other) = (&**left, &**right) {
                        return self.compile_string_comparison(
                            other,
                            lit,
                            matches!(op, BinaryOp::Equal),
                        );
                    } else if let (other, Expr::String(lit)) = (&**left, &**right) {
                        return self.compile_string_comparison(
                            other,
                            lit,
                            matches!(op, BinaryOp::Equal),
                        );
                    }
                }
                // Implement short-circuit for logical OR (||) and logical AND (&&)
                if matches!(op, BinaryOp::LogicalOr) {
                    // Evaluate LHS to boolean (non-zero => true)
                    let lhs_val = self.compile_expr(left)?;
                    let lhs_int = match lhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical OR requires integer operands".to_string(),
                            ))
                        }
                    };
                    let lhs_zero = lhs_int.get_type().const_zero();
                    let lhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            lhs_int,
                            lhs_zero,
                            "lor_lhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                    // Prepare control flow blocks
                    let curr_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block".to_string())
                    })?;
                    let func = curr_block
                        .get_parent()
                        .ok_or_else(|| CodeGenError::LLVMError("No parent function".to_string()))?;
                    let rhs_block = self.context.append_basic_block(func, "lor_rhs");
                    let merge_block = self.context.append_basic_block(func, "lor_merge");

                    // If lhs is true, jump directly to merge (short-circuit)
                    self.builder
                        .build_conditional_branch(lhs_bool, merge_block, rhs_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // RHS path: compute boolean only if needed
                    self.builder.position_at_end(rhs_block);
                    let rhs_val = self.compile_expr(right)?;
                    let rhs_int = match rhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical OR requires integer operands".to_string(),
                            ))
                        }
                    };
                    let rhs_zero = rhs_int.get_type().const_zero();
                    let rhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            rhs_int,
                            rhs_zero,
                            "lor_rhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    // Capture the actual block where RHS computation ended
                    let rhs_end_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block after RHS".to_string())
                    })?;
                    self.builder
                        .build_unconditional_branch(merge_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Merge: phi of i1: true from LHS-true, RHS bool from rhs_block
                    self.builder.position_at_end(merge_block);
                    let i1 = self.context.bool_type();
                    let phi = self
                        .builder
                        .build_phi(i1, "lor_phi")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let one = i1.const_int(1, false);
                    phi.add_incoming(&[(&one, curr_block), (&rhs_bool, rhs_end_block)]);
                    return Ok(phi.as_basic_value());
                } else if matches!(op, BinaryOp::LogicalAnd) {
                    // Evaluate LHS to boolean (non-zero => true)
                    let lhs_val = self.compile_expr(left)?;
                    let lhs_int = match lhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical AND requires integer operands".to_string(),
                            ))
                        }
                    };
                    let lhs_zero = lhs_int.get_type().const_zero();
                    let lhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            lhs_int,
                            lhs_zero,
                            "land_lhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                    // Prepare control flow: if lhs is true, evaluate rhs; else short-circuit to false
                    let curr_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block".to_string())
                    })?;
                    let func = curr_block
                        .get_parent()
                        .ok_or_else(|| CodeGenError::LLVMError("No parent function".to_string()))?;
                    let rhs_block = self.context.append_basic_block(func, "land_rhs");
                    let merge_block = self.context.append_basic_block(func, "land_merge");

                    // If lhs is true, go compute rhs; else jump to merge with false
                    self.builder
                        .build_conditional_branch(lhs_bool, rhs_block, merge_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // RHS path
                    self.builder.position_at_end(rhs_block);
                    let rhs_val = self.compile_expr(right)?;
                    let rhs_int = match rhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical AND requires integer operands".to_string(),
                            ))
                        }
                    };
                    let rhs_zero = rhs_int.get_type().const_zero();
                    let rhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            rhs_int,
                            rhs_zero,
                            "land_rhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let rhs_end_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block after RHS".to_string())
                    })?;
                    self.builder
                        .build_unconditional_branch(merge_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Merge: phi(i1) with false from LHS=false path, RHS bool from rhs path
                    self.builder.position_at_end(merge_block);
                    let i1 = self.context.bool_type();
                    let phi = self
                        .builder
                        .build_phi(i1, "land_phi")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let zero = i1.const_zero();
                    phi.add_incoming(&[(&rhs_bool, rhs_end_block), (&zero, curr_block)]);
                    return Ok(phi.as_basic_value());
                }

                // Default eager evaluation for other binary ops
                let left_val = self.compile_expr(left)?;
                let right_val = self.compile_expr(right)?;
                self.compile_binary_op(left_val, op.clone(), right_val)
            }
            Expr::MemberAccess(_, _) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
            Expr::PointerDeref(_) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
            Expr::AddressOf(inner) => {
                // Address-of with ASLR-aware hint: compute runtime address using module hint
                let var = self.query_dwarf_for_complex_expr(inner)?.ok_or_else(|| {
                    super::context::CodeGenError::TypeError(
                        "cannot take address of unresolved expression".to_string(),
                    )
                })?;
                // Use current resolved hint if available (set during DWARF resolution)
                let module_hint = self.current_resolved_var_module_path.clone();
                match self.evaluation_result_to_address_with_hint(
                    &var.evaluation_result,
                    None,
                    module_hint.as_deref(),
                ) {
                    Ok(addr_i64) => {
                        let ptr_ty = self.context.ptr_type(AddressSpace::default());
                        let as_ptr = self
                            .builder
                            .build_int_to_ptr(addr_i64, ptr_ty, "addr_as_ptr")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        Ok(as_ptr.into())
                    }
                    Err(_) => Err(super::context::CodeGenError::TypeError(
                        "cannot take address of rvalue".to_string(),
                    )),
                }
            }
            Expr::ArrayAccess(_, _) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
            Expr::ChainAccess(_) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
        }
    }

    /// Handle special variables like $pid, $tid, etc.
    pub fn handle_special_variable(&mut self, name: &str) -> Result<BasicValueEnum<'ctx>> {
        match name {
            "pid" => {
                // Use BPF helper to get current PID
                let pid_tgid = self.get_current_pid_tgid()?;
                let pid_mask = self.context.i64_type().const_int(0xFFFFFFFF, false);
                let pid = self
                    .builder
                    .build_and(pid_tgid, pid_mask, "pid")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(pid.into())
            }
            "tid" => {
                // Use BPF helper to get current TID (thread ID)
                let pid_tgid = self.get_current_pid_tgid()?;
                let tid = self
                    .builder
                    .build_right_shift(
                        pid_tgid,
                        self.context.i64_type().const_int(32, false),
                        false,
                        "tid",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(tid.into())
            }
            "timestamp" => {
                // Use BPF helper to get current timestamp
                let ts = self.get_current_timestamp()?;
                Ok(ts.into())
            }
            _ => {
                let supported = ["$pid", "$tid", "$timestamp"].join(", ");
                Err(CodeGenError::NotImplemented(format!(
                    "Unknown special variable '${name}'. Supported: {supported}"
                )))
            }
        }
    }

    /// Compile binary operations
    pub fn compile_binary_op(
        &mut self,
        left: BasicValueEnum<'ctx>,
        op: BinaryOp,
        right: BasicValueEnum<'ctx>,
    ) -> Result<BasicValueEnum<'ctx>> {
        use inkwell::values::BasicValueEnum::*;

        // Debug logging to understand the actual types
        debug!("compile_binary_op: op={:?}", op);
        debug!("compile_binary_op: left type = {:?}", left.get_type());
        debug!("compile_binary_op: right type = {:?}", right.get_type());
        match &left {
            IntValue(iv) => debug!(
                "compile_binary_op: left is IntValue with bit width {}",
                iv.get_type().get_bit_width()
            ),
            FloatValue(_) => debug!("compile_binary_op: left is FloatValue"),
            PointerValue(_) => debug!("compile_binary_op: left is PointerValue"),
            _ => debug!("compile_binary_op: left is other type"),
        }
        match &right {
            IntValue(iv) => debug!(
                "compile_binary_op: right is IntValue with bit width {}",
                iv.get_type().get_bit_width()
            ),
            FloatValue(_) => debug!("compile_binary_op: right is FloatValue"),
            PointerValue(_) => debug!("compile_binary_op: right is PointerValue"),
            _ => debug!("compile_binary_op: right is other type"),
        }

        match (left, right) {
            (IntValue(left_int), IntValue(right_int)) => {
                let result = match op {
                    BinaryOp::Add => self
                        .builder
                        .build_int_add(left_int, right_int, "add")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Subtract => self
                        .builder
                        .build_int_sub(left_int, right_int, "sub")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Multiply => self
                        .builder
                        .build_int_mul(left_int, right_int, "mul")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Divide => self
                        .builder
                        .build_int_signed_div(left_int, right_int, "div")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    // Comparison operators
                    BinaryOp::Equal => {
                        let result = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::EQ, left_int, right_int, "eq")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::NotEqual => {
                        let result = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, left_int, right_int, "ne")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LessThan => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SLT,
                                left_int,
                                right_int,
                                "lt",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LessEqual => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SLE,
                                left_int,
                                right_int,
                                "le",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::GreaterThan => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SGT,
                                left_int,
                                right_int,
                                "gt",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::GreaterEqual => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SGE,
                                left_int,
                                right_int,
                                "ge",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    // Logical operators with boolean semantics (non-zero is true)
                    BinaryOp::LogicalAnd => {
                        let lz = left_int.get_type().const_zero();
                        let rz = right_int.get_type().const_zero();
                        let lbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, left_int, lz, "lhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let rbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, right_int, rz, "rhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let result = self
                            .builder
                            .build_and(lbool, rbool, "and_bool")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LogicalOr => {
                        let lz = left_int.get_type().const_zero();
                        let rz = right_int.get_type().const_zero();
                        let lbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, left_int, lz, "lhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let rbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, right_int, rz, "rhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let result = self
                            .builder
                            .build_or(lbool, rbool, "or_bool")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                };
                Ok(result.into())
            }
            // Pointer equality/inequality comparisons
            (PointerValue(lp), IntValue(ri)) | (IntValue(ri), PointerValue(lp)) => {
                match op {
                    BinaryOp::Equal | BinaryOp::NotEqual => {
                        let lpi64 = self
                            .builder
                            .build_ptr_to_int(lp, self.context.i64_type(), "ptr_as_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        // Normalize RHS to i64
                        let rbw = ri.get_type().get_bit_width();
                        let ri64 = if rbw < 64 {
                            self.builder
                                .build_int_z_extend(ri, self.context.i64_type(), "rhs_zext_i64")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        } else if rbw > 64 {
                            self.builder
                                .build_int_truncate(ri, self.context.i64_type(), "rhs_trunc_i64")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        } else {
                            ri
                        };
                        let pred = if matches!(op, BinaryOp::Equal) {
                            inkwell::IntPredicate::EQ
                        } else {
                            inkwell::IntPredicate::NE
                        };
                        let cmp = self
                            .builder
                            .build_int_compare(pred, lpi64, ri64, "ptr_cmp")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        Ok(cmp.into())
                    }
                    _ => Err(CodeGenError::TypeError(format!(
                        "Type mismatch in binary operation {op:?}"
                    ))),
                }
            }
            (PointerValue(lp), PointerValue(rp)) => match op {
                BinaryOp::Equal | BinaryOp::NotEqual => {
                    let lpi64 = self
                        .builder
                        .build_ptr_to_int(lp, self.context.i64_type(), "l_ptr_as_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let rpi64 = self
                        .builder
                        .build_ptr_to_int(rp, self.context.i64_type(), "r_ptr_as_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let pred = if matches!(op, BinaryOp::Equal) {
                        inkwell::IntPredicate::EQ
                    } else {
                        inkwell::IntPredicate::NE
                    };
                    let cmp = self
                        .builder
                        .build_int_compare(pred, lpi64, rpi64, "ptr_ptr_cmp")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(cmp.into())
                }
                _ => Err(CodeGenError::TypeError(format!(
                    "Type mismatch in binary operation {op:?}"
                ))),
            },
            (FloatValue(left_float), FloatValue(right_float)) => match op {
                BinaryOp::Add => {
                    let result = self
                        .builder
                        .build_float_add(left_float, right_float, "add")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::Subtract => {
                    let result = self
                        .builder
                        .build_float_sub(left_float, right_float, "sub")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::Multiply => {
                    let result = self
                        .builder
                        .build_float_mul(left_float, right_float, "mul")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::Divide => {
                    let result = self
                        .builder
                        .build_float_div(left_float, right_float, "div")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                // Float comparison operators
                BinaryOp::Equal => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OEQ,
                            left_float,
                            right_float,
                            "eq",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::NotEqual => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::ONE,
                            left_float,
                            right_float,
                            "ne",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::LessThan => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OLT,
                            left_float,
                            right_float,
                            "lt",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::LessEqual => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OLE,
                            left_float,
                            right_float,
                            "le",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::GreaterThan => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OGT,
                            left_float,
                            right_float,
                            "gt",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::GreaterEqual => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OGE,
                            left_float,
                            right_float,
                            "ge",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                _ => Err(CodeGenError::NotImplemented(format!(
                    "Float binary operation {op:?} not implemented"
                ))),
            },
            _ => Err(CodeGenError::TypeError(format!(
                "Type mismatch in binary operation {op:?}"
            ))),
        }
    }

    /// Compile member access (struct.field)
    pub fn compile_member_access(
        &mut self,
        obj_expr: &Expr,
        field: &str,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Create a MemberAccess expression and use the unified DWARF compilation
        let member_access_expr = Expr::MemberAccess(Box::new(obj_expr.clone()), field.to_string());
        self.compile_dwarf_expression(&member_access_expr)
    }

    /// Compile pointer dereference (*ptr)
    pub fn compile_pointer_deref(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>> {
        // Create a PointerDeref expression and use the unified DWARF compilation
        let pointer_deref_expr = Expr::PointerDeref(Box::new(expr.clone()));
        self.compile_dwarf_expression(&pointer_deref_expr)
    }

    /// Compile array access (arr[index])
    pub fn compile_array_access(
        &mut self,
        array_expr: &Expr,
        index_expr: &Expr,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Create an ArrayAccess expression and use the unified DWARF compilation
        let array_access_expr =
            Expr::ArrayAccess(Box::new(array_expr.clone()), Box::new(index_expr.clone()));
        self.compile_dwarf_expression(&array_access_expr)
    }

    /// Compile chain access (person.name.first)
    pub fn compile_chain_access(&mut self, chain: &[String]) -> Result<BasicValueEnum<'ctx>> {
        // Create a ChainAccess expression and use the unified DWARF compilation
        let chain_access_expr = Expr::ChainAccess(chain.to_vec());
        self.compile_dwarf_expression(&chain_access_expr)
    }

    /// Unified DWARF expression compilation
    pub fn compile_dwarf_expression(
        &mut self,
        expr: &crate::script::Expr,
    ) -> Result<BasicValueEnum<'ctx>> {
        debug!(
            "compile_dwarf_expression: Compiling complex expression: {:?}",
            expr
        );

        // Query DWARF for the complex expression
        let compile_context = self.get_compile_time_context()?.clone();
        let variable_with_eval = match self.query_dwarf_for_complex_expr(expr)? {
            Some(var) => var,
            None => {
                let expr_str = Self::expr_to_debug_string(expr);
                return Err(CodeGenError::VariableNotFound(expr_str));
            }
        };

        let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
        })?;

        debug!(
            "compile_dwarf_expression: Found DWARF info for expression '{}' with type: {:?}",
            variable_with_eval.name, dwarf_type
        );

        // Use the unified evaluation logic to generate LLVM IR
        self.evaluate_result_to_llvm_value(
            &variable_with_eval.evaluation_result,
            dwarf_type,
            &variable_with_eval.name,
            compile_context.pc_address,
        )
    }

    /// Helper: Convert expression to string for debugging
    fn expr_to_debug_string(expr: &crate::script::Expr) -> String {
        use crate::script::Expr;

        match expr {
            Expr::Variable(name) => name.clone(),
            Expr::MemberAccess(obj, field) => {
                format!("{}.{}", Self::expr_to_debug_string(obj), field)
            }
            Expr::ArrayAccess(arr, _) => format!("{}[index]", Self::expr_to_debug_string(arr)),
            Expr::ChainAccess(chain) => chain.join("."),
            Expr::PointerDeref(expr) => format!("*{}", Self::expr_to_debug_string(expr)),
            _ => "expr".to_string(),
        }
    }
}

impl<'ctx> EbpfContext<'ctx> {
    /// Compile comparison between a DWARF-side expression and a script string literal.
    /// Supports char* and char[N] according to design in string_comparison.md.
    fn compile_string_comparison(
        &mut self,
        dwarf_expr: &Expr,
        lit: &str,
        is_equal: bool,
    ) -> Result<BasicValueEnum<'ctx>> {
        use ghostscope_dwarf::TypeInfo as TI;

        // Query DWARF for the non-string side to obtain evaluation and type info
        let var = self
            .query_dwarf_for_complex_expr(dwarf_expr)?
            .ok_or_else(|| {
                CodeGenError::TypeError(
                    "string comparison requires DWARF variable/expression".into(),
                )
            })?;
        // Try DWARF type first; if unavailable, fall back to type_name string parsing
        let dwarf_type_opt = var.dwarf_type.as_ref();

        enum ParsedKind {
            PtrChar,
            ArrChar(Option<u32>),
            Other,
        }
        fn parse_type_name(name: &str) -> ParsedKind {
            let lower = name.to_lowercase();
            let has_char = lower.contains("char");
            let is_ptr = lower.contains('*');
            if has_char && is_ptr {
                return ParsedKind::PtrChar;
            }
            if has_char && lower.contains('[') {
                // Try to extract N inside brackets
                let mut n: Option<u32> = None;
                if let Some(start) = lower.find('[') {
                    if let Some(end) = lower[start + 1..].find(']') {
                        let inside = &lower[start + 1..start + 1 + end];
                        let digits: String =
                            inside.chars().filter(|c| c.is_ascii_digit()).collect();
                        if !digits.is_empty() {
                            if let Ok(v) = digits.parse::<u32>() {
                                n = Some(v);
                            }
                        }
                    }
                }
                return ParsedKind::ArrChar(n);
            }
            ParsedKind::Other
        }

        // Helper to peel typedef/qualifier wrappers
        fn unwrap_aliases(t: &TI) -> &TI {
            let mut cur = t;
            loop {
                match cur {
                    TI::TypedefType {
                        underlying_type, ..
                    } => cur = underlying_type.as_ref(),
                    TI::QualifiedType {
                        underlying_type, ..
                    } => cur = underlying_type.as_ref(),
                    _ => break,
                }
            }
            cur
        }

        // Compute runtime address of the DWARF expression
        let module_hint = self.current_resolved_var_module_path.clone();
        let status_ptr = if self.condition_context_active {
            Some(self.get_or_create_cond_error_global())
        } else {
            None
        };
        let addr = self.evaluation_result_to_address_with_hint(
            &var.evaluation_result,
            status_ptr,
            module_hint.as_deref(),
        )?;

        let lit_bytes = lit.as_bytes();
        let lit_len = lit_bytes.len() as u32;
        let one = self.context.bool_type().const_int(1, false);
        let zero = self.context.bool_type().const_zero();

        // Build final boolean accumulator
        let result = match dwarf_type_opt.map(unwrap_aliases) {
            // char* / const char*
            Some(TI::PointerType { target_type, .. }) => {
                // Ensure pointee is char-like
                let base = unwrap_aliases(target_type.as_ref());
                let is_char_like = matches!(base, TI::BaseType { name, size, .. } if name.contains("char") && *size == 1);
                if !is_char_like {
                    return Err(CodeGenError::TypeError(
                        "automatic string comparison only supports char*".into(),
                    ));
                }

                // Evaluate expression to pointer value and read up to L+1 bytes
                let val_any = self.evaluate_result_to_llvm_value(
                    &var.evaluation_result,
                    var.dwarf_type.as_ref().unwrap(),
                    &var.name,
                    self.get_compile_time_context()?.pc_address,
                )?;
                let ptr_i64 = match val_any {
                    BasicValueEnum::IntValue(iv) => iv,
                    BasicValueEnum::PointerValue(pv) => self
                        .builder
                        .build_ptr_to_int(pv, self.context.i64_type(), "ptr_as_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    _ => {
                        return Err(CodeGenError::TypeError(
                            "pointer value must be integer or pointer".into(),
                        ))
                    }
                };
                let need = lit_len + 1;
                let (buf_global, ret_len, arr_ty) =
                    self.read_user_cstr_into_buffer(ptr_i64, need, "_gs_strbuf")?;

                // ret_len must equal L+1
                let i64_ty = self.context.i64_type();
                let expect_len = i64_ty.const_int(need as u64, false);
                let len_ok = self
                    .builder
                    .build_int_compare(inkwell::IntPredicate::EQ, ret_len, expect_len, "str_len_ok")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                // buf[L] must be '\0'
                let i32_ty = self.context.i32_type();
                let idx0 = i32_ty.const_zero();
                let idx_l = i32_ty.const_int(lit_len as u64, false);
                let char_ptr = unsafe {
                    self.builder
                        .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                };
                let c = self
                    .builder
                    .build_load(self.context.i8_type(), char_ptr, "c_l")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let c = match c {
                    BasicValueEnum::IntValue(iv) => iv,
                    _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                };
                let nul_ok = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        c,
                        self.context.i8_type().const_zero(),
                        "nul_ok",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                // Compare first L bytes using XOR/OR accumulation to reduce branchiness
                let mut acc = self.context.i8_type().const_zero();
                for (i, b) in lit_bytes.iter().enumerate() {
                    let idx_i = i32_ty.const_int(i as u64, false);
                    let ptr_i = unsafe {
                        self.builder
                            .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    };
                    let ch = self
                        .builder
                        .build_load(self.context.i8_type(), ptr_i, "ch")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let ch = match ch {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                    };
                    let expect = self.context.i8_type().const_int(*b as u64, false);
                    let diff = self
                        .builder
                        .build_xor(ch, expect, "diff")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    acc = self
                        .builder
                        .build_or(acc, diff, "acc_or")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                }
                let eq_bytes = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        acc,
                        self.context.i8_type().const_zero(),
                        "acc_zero",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let ok1 = self
                    .builder
                    .build_and(len_ok, nul_ok, "ok_len_nul")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                self.builder
                    .build_and(ok1, eq_bytes, "str_eq")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            }
            // char[N]
            Some(TI::ArrayType {
                element_type,
                element_count,
                total_size,
            }) => {
                let elem = unwrap_aliases(element_type.as_ref());
                let is_char_like = matches!(elem, TI::BaseType { name, size, .. } if name.contains("char") && *size == 1);
                if !is_char_like {
                    return Err(CodeGenError::TypeError(
                        "automatic string comparison only supports char[N]".into(),
                    ));
                }
                // Determine N (element count)
                let n_opt = element_count.or_else(|| total_size.map(|ts| ts));
                let n = if let Some(nv) = n_opt { nv as u32 } else { 0 };
                if n == 0 {
                    return Err(CodeGenError::TypeError(
                        "array size unknown for char[N] comparison".into(),
                    ));
                }
                // If L+1 > N, compile-time false
                if lit_len + 1 > n {
                    // Return const false (or true if '!=' requested)
                    return Ok((if is_equal { zero } else { one }).into());
                }
                // Read exactly L+1 bytes
                let (buf_global, status, arr_ty) =
                    self.read_user_bytes_into_buffer(addr, lit_len + 1, "_gs_arrbuf")?;
                // status == 0
                let status_ok = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        status,
                        self.context.i64_type().const_zero(),
                        "rd_ok",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                // buf[L] must be '\0'
                let i32_ty = self.context.i32_type();
                let idx0 = i32_ty.const_zero();
                let idx_l = i32_ty.const_int(lit_len as u64, false);
                let char_ptr = unsafe {
                    self.builder
                        .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                };
                let c = self
                    .builder
                    .build_load(self.context.i8_type(), char_ptr, "c_l")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let c = match c {
                    BasicValueEnum::IntValue(iv) => iv,
                    _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                };
                let nul_ok = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        c,
                        self.context.i8_type().const_zero(),
                        "nul_ok",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                // Compare first L bytes using XOR/OR accumulation
                let mut acc = self.context.i8_type().const_zero();
                for (i, b) in lit_bytes.iter().enumerate() {
                    let idx_i = i32_ty.const_int(i as u64, false);
                    let ptr_i = unsafe {
                        self.builder
                            .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    };
                    let ch = self
                        .builder
                        .build_load(self.context.i8_type(), ptr_i, "ch")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let ch = match ch {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                    };
                    let expect = self.context.i8_type().const_int(*b as u64, false);
                    let diff = self
                        .builder
                        .build_xor(ch, expect, "diff")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    acc = self
                        .builder
                        .build_or(acc, diff, "acc_or")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                }
                let eq_bytes = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        acc,
                        self.context.i8_type().const_zero(),
                        "acc_zero",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let ok1 = self
                    .builder
                    .build_and(status_ok, nul_ok, "ok_len_nul")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                self.builder
                    .build_and(ok1, eq_bytes, "arr_eq")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            }
            None => {
                // Fallback using type_name string
                match parse_type_name(&var.type_name) {
                    ParsedKind::PtrChar => {
                        // Load pointer value from variable location (assume 64-bit)
                        let ptr_any = self
                            .generate_memory_read(addr, ghostscope_dwarf::MemoryAccessSize::U64)?;
                        let ptr_i64 = match ptr_any {
                            BasicValueEnum::IntValue(iv) => iv,
                            _ => {
                                return Err(CodeGenError::LLVMError(
                                    "pointer load did not return integer".to_string(),
                                ))
                            }
                        };
                        let need = lit_len + 1;
                        let (buf_global, ret_len, arr_ty) =
                            self.read_user_cstr_into_buffer(ptr_i64, need, "_gs_strbuf")?;

                        let i64_ty = self.context.i64_type();
                        let expect_len = i64_ty.const_int(need as u64, false);
                        let len_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                ret_len,
                                expect_len,
                                "str_len_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                        let i32_ty = self.context.i32_type();
                        let idx0 = i32_ty.const_zero();
                        let idx_l = i32_ty.const_int(lit_len as u64, false);
                        let char_ptr = unsafe {
                            self.builder
                                .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        };
                        let c = self
                            .builder
                            .build_load(self.context.i8_type(), char_ptr, "c_l")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let c = match c {
                            BasicValueEnum::IntValue(iv) => iv,
                            _ => {
                                return Err(CodeGenError::LLVMError(
                                    "load did not return i8".into(),
                                ))
                            }
                        };
                        let nul_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                c,
                                self.context.i8_type().const_zero(),
                                "nul_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                        let mut acc = self.context.i8_type().const_zero();
                        for (i, b) in lit_bytes.iter().enumerate() {
                            let idx_i = i32_ty.const_int(i as u64, false);
                            let ptr_i = unsafe {
                                self.builder
                                    .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                            };
                            let ch = self
                                .builder
                                .build_load(self.context.i8_type(), ptr_i, "ch")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            let ch = match ch {
                                BasicValueEnum::IntValue(iv) => iv,
                                _ => {
                                    return Err(CodeGenError::LLVMError(
                                        "load did not return i8".into(),
                                    ))
                                }
                            };
                            let expect = self.context.i8_type().const_int(*b as u64, false);
                            let diff = self
                                .builder
                                .build_xor(ch, expect, "diff")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            acc = self
                                .builder
                                .build_or(acc, diff, "acc_or")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        }
                        let eq_bytes = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                acc,
                                self.context.i8_type().const_zero(),
                                "acc_zero",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let ok1 = self
                            .builder
                            .build_and(len_ok, nul_ok, "ok_len_nul")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        self.builder
                            .build_and(ok1, eq_bytes, "str_eq")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    }
                    ParsedKind::ArrChar(n_opt) => {
                        // If we know N and L+1>N, return false; else read L+1 bytes
                        if let Some(n) = n_opt {
                            if lit_len + 1 > n {
                                return Ok((if is_equal { zero } else { one }).into());
                            }
                        }
                        let (buf_global, status, arr_ty) =
                            self.read_user_bytes_into_buffer(addr, lit_len + 1, "_gs_arrbuf")?;
                        let status_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                status,
                                self.context.i64_type().const_zero(),
                                "rd_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let i32_ty = self.context.i32_type();
                        let idx0 = i32_ty.const_zero();
                        let idx_l = i32_ty.const_int(lit_len as u64, false);
                        let char_ptr = unsafe {
                            self.builder
                                .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        };
                        let c = self
                            .builder
                            .build_load(self.context.i8_type(), char_ptr, "c_l")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let c = match c {
                            BasicValueEnum::IntValue(iv) => iv,
                            _ => {
                                return Err(CodeGenError::LLVMError(
                                    "load did not return i8".into(),
                                ))
                            }
                        };
                        let nul_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                c,
                                self.context.i8_type().const_zero(),
                                "nul_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let mut acc = self.context.i8_type().const_zero();
                        for (i, b) in lit_bytes.iter().enumerate() {
                            let idx_i = i32_ty.const_int(i as u64, false);
                            let ptr_i = unsafe {
                                self.builder
                                    .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                            };
                            let ch = self
                                .builder
                                .build_load(self.context.i8_type(), ptr_i, "ch")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            let ch = match ch {
                                BasicValueEnum::IntValue(iv) => iv,
                                _ => {
                                    return Err(CodeGenError::LLVMError(
                                        "load did not return i8".into(),
                                    ))
                                }
                            };
                            let expect = self.context.i8_type().const_int(*b as u64, false);
                            let diff = self
                                .builder
                                .build_xor(ch, expect, "diff")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            acc = self
                                .builder
                                .build_or(acc, diff, "acc_or")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        }
                        let eq_bytes = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                acc,
                                self.context.i8_type().const_zero(),
                                "acc_zero",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let ok1 = self
                            .builder
                            .build_and(status_ok, nul_ok, "ok_len_nul")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        self.builder
                            .build_and(ok1, eq_bytes, "arr_eq")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    }
                    ParsedKind::Other => {
                        return Err(CodeGenError::TypeError(format!(
                            "string comparison unsupported for type name '{}' without DWARF type",
                            var.type_name
                        )));
                    }
                }
            }
            Some(_) => {
                return Err(CodeGenError::TypeError(
                    "string comparison only supports char* or char[N]".into(),
                ));
            }
        };

        // Apply == / !=
        let final_bool = if is_equal {
            result
        } else {
            self.builder
                .build_not(result, "not_eq")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        Ok(final_bool.into())
    }
}

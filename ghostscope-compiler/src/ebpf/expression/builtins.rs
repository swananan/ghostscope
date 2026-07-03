use crate::ebpf::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use crate::script::Expr;
use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user;
use ghostscope_dwarf::TypeInfo as DwarfType;
use inkwell::values::{BasicValueEnum, IntValue};
use inkwell::AddressSpace;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Builtin memcmp (boolean variant): returns true iff first `len` bytes equal.
    /// Supports dynamic `len` (expr), clamped to [0, compare_cap].
    pub(super) fn compile_memcmp_builtin(
        &mut self,
        a_expr: &Expr,
        b_expr: &Expr,
        len_expr: &Expr,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Note: constant hex/len validation happens at parse-time; dynamic cases are handled at runtime by masking bytes.

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
        let func = self.current_function("compile memcmp length branch")?;
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
        let zero_block = self.current_insert_block("finish memcmp zero-length block")?;

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
                // SAFETY: buf_a is a cap-sized array and i is bounded by cap.
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
            let ptr_a = self.resolve_runtime_address_from_expr(a_expr)?;
            let offsets_found_a = ptr_a.offsets_found;
            let dst_a = self
                .builder
                .build_bit_cast(buf_a, ptr_ty, "memcmp_dst_a")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let base_src_a = self
                .builder
                .build_int_to_ptr(ptr_a.value, ptr_ty, "memcmp_src_a")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let null_ptr = ptr_ty.const_null();
            let src_a = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    offsets_found_a,
                    base_src_a.into(),
                    null_ptr.into(),
                    "memcmp_src_a_or_null",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                .into_pointer_value();
            let zero_i32 = self.context.i32_type().const_zero();
            let effective_len_a = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    offsets_found_a,
                    sel_len.into(),
                    zero_i32.into(),
                    "memcmp_len_a_or_zero",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                .into_int_value();
            let ret_a = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[dst_a, effective_len_a.into(), src_a.into()],
                    self.context.i64_type().into(),
                    "probe_read_user_memcmp_a",
                )?
                .into_int_value();
            let i64_ty = self.context.i64_type();
            let eq_a = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    ret_a,
                    i64_ty.const_zero(),
                    "memcmp_ok_a",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder
                .build_and(eq_a, offsets_found_a, "memcmp_ok_a")
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
                // SAFETY: buf_b is a cap-sized array and i is bounded by cap.
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
            let ptr_b = self.resolve_runtime_address_from_expr(b_expr)?;
            let offsets_found_b = ptr_b.offsets_found;
            let dst_b = self
                .builder
                .build_bit_cast(buf_b, ptr_ty, "memcmp_dst_b")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let base_src_b = self
                .builder
                .build_int_to_ptr(ptr_b.value, ptr_ty, "memcmp_src_b")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let null_ptr = ptr_ty.const_null();
            let src_b = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    offsets_found_b,
                    base_src_b.into(),
                    null_ptr.into(),
                    "memcmp_src_b_or_null",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                .into_pointer_value();
            let zero_i32 = self.context.i32_type().const_zero();
            let effective_len_b = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    offsets_found_b,
                    sel_len.into(),
                    zero_i32.into(),
                    "memcmp_len_b_or_zero",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                .into_int_value();
            let ret_b = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[dst_b, effective_len_b.into(), src_b.into()],
                    self.context.i64_type().into(),
                    "probe_read_user_memcmp_b",
                )?
                .into_int_value();
            let i64_ty = self.context.i64_type();
            let eq_b = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    ret_b,
                    i64_ty.const_zero(),
                    "memcmp_ok_b",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder
                .build_and(eq_b, offsets_found_b, "memcmp_ok_b")
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
            let func = self.current_function("compile memcmp condition error branch")?;
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
            let cur_fn = self.current_function("compile memcmp failure address branch")?;
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
            // SAFETY: i is bounded by cmp_bound, which is clamped to the buffer cap.
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
            // SAFETY: i is bounded by cmp_bound, which is clamped to the buffer cap.
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
        let nz_block = self.current_insert_block("finish memcmp non-zero block")?;

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
    fn compile_bounded_compare_len_i32(
        &mut self,
        len_expr: &Expr,
        max_len: u32,
        name_prefix: &str,
    ) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
        let len_val = self.compile_expr(len_expr)?;
        let len_iv = match len_val {
            BasicValueEnum::IntValue(iv) => iv,
            _ => {
                return Err(CodeGenError::TypeError(format!(
                    "{name_prefix} length must be an integer expression"
                )))
            }
        };
        let i32_ty = self.context.i32_type();
        let len_i32 = if len_iv.get_type().get_bit_width() > 32 {
            self.builder
                .build_int_truncate(len_iv, i32_ty, &format!("{name_prefix}_len_trunc"))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        } else if len_iv.get_type().get_bit_width() < 32 {
            self.builder
                .build_int_z_extend(len_iv, i32_ty, &format!("{name_prefix}_len_zext"))
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
                &format!("{name_prefix}_len_neg"),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let len_nn = self
            .builder
            .build_select(is_neg, zero_i32, len_i32, &format!("{name_prefix}_len_nn"))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let max_const = i32_ty.const_int(max_len as u64, false);
        let gt = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                len_nn,
                max_const,
                &format!("{name_prefix}_len_gt"),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let bounded_len = self
            .builder
            .build_select(gt, max_const, len_nn, &format!("{name_prefix}_len_sel"))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let is_zero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                bounded_len,
                zero_i32,
                &format!("{name_prefix}_len_is_zero"),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        Ok((bounded_len, is_zero))
    }

    pub(super) fn compile_strncmp_builtin(
        &mut self,
        dwarf_expr: &Expr,
        lit: &str,
        n_expr: &Expr,
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
            if let Expr::Int(n) = n_expr {
                let n_usize = std::cmp::min(
                    (*n).max(0) as usize,
                    self.compile_options.compare_cap as usize,
                );
                let content_len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let cmp_len = std::cmp::min(n_usize, std::cmp::min(content_len, lit.len()));
                let equal = bytes.get(0..cmp_len).unwrap_or(&[])
                    == lit.as_bytes().get(0..cmp_len).unwrap_or(&[]);
                let bool_val = self
                    .context
                    .bool_type()
                    .const_int(if equal { 1 } else { 0 }, false);
                return Ok(bool_val.into());
            }

            // Treat as bounded byte compare between two immediate strings
            let cap = self.compile_options.compare_cap as usize;
            let content_len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            let cmp_bound = std::cmp::min(cap, std::cmp::min(content_len, lit.len())) as u32;
            if cmp_bound == 0 {
                return Ok(self.context.bool_type().const_int(1, false).into());
            }
            let (bounded_len, _len_is_zero) =
                self.compile_bounded_compare_len_i32(n_expr, cmp_bound, "strncmp")?;
            let i32_ty = self.context.i32_type();
            let i8_ty = self.context.i8_type();
            let mut acc = i8_ty.const_zero();
            for (i, (byte, lit_byte)) in bytes
                .iter()
                .copied()
                .zip(lit.as_bytes().iter().copied())
                .take(cmp_bound as usize)
                .enumerate()
            {
                let active = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::UGT,
                        bounded_len,
                        i32_ty.const_int(i as u64, false),
                        "strncmp_imm_active",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let diff = i8_ty.const_int((byte ^ lit_byte) as u64, false);
                let active_diff = self
                    .builder
                    .build_select(active, diff, i8_ty.const_zero(), "strncmp_imm_diff")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    .into_int_value();
                acc = self
                    .builder
                    .build_or(acc, active_diff, "strncmp_imm_acc")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            }
            let equal = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    acc,
                    i8_ty.const_zero(),
                    "strncmp_imm_eq",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            return Ok(equal.into());
        }

        // Determine pointer value (i64) of the target memory (DWARF or alias)
        // Prefer DWARF resolution for richer status/hints; fallback to generic pointer resolver.
        let ptr_i64 = match self.query_dwarf_for_complex_expr(dwarf_expr)? {
            Some(var) => {
                if let Some(ty) = var.dwarf_type.as_ref() {
                    let ty = ghostscope_dwarf::strip_type_aliases(ty);
                    match ty {
                        DwarfType::PointerType { .. } => {
                            let pc_address = self.get_compile_time_context()?.pc_address;
                            let val_any =
                                self.variable_read_plan_to_llvm_value(&var, pc_address, None)?;
                            match val_any {
                                BasicValueEnum::IntValue(iv) => {
                                    RuntimeAddress::available(iv, self.context)
                                }
                                BasicValueEnum::PointerValue(pv) => self
                                    .builder
                                    .build_ptr_to_int(pv, self.context.i64_type(), "ptr_as_i64")
                                    .map(|value| RuntimeAddress::available(value, self.context))
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                                _ => {
                                    return Err(CodeGenError::TypeError(
                                        "strncmp requires pointer/integer value for pointer; got unsupported DWARF value".into(),
                                    ))
                                }
                            }
                        }
                        DwarfType::ArrayType { .. } => {
                            let status_ptr = if self.condition_context_active {
                                Some(self.get_or_create_cond_error_global())
                            } else {
                                None
                            };
                            let pc_address = self.get_compile_time_context()?.pc_address;
                            self.variable_read_plan_to_runtime_address(
                                &var, pc_address, status_ptr,
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
                self.resolve_runtime_address_from_expr(dwarf_expr).map_err(|_| {
                    CodeGenError::TypeError(
                        "strncmp requires at least one string argument, and the other side must be an address expression (DWARF pointer/array or alias)".to_string(),
                    )
                })?
            }
        };

        let cap = self.compile_options.compare_cap;
        let cmp_bound = std::cmp::min(lit.len() as u32, cap);
        if cmp_bound == 0 {
            return Ok(self.context.bool_type().const_int(1, false).into());
        }
        let (bounded_len, len_is_zero) =
            self.compile_bounded_compare_len_i32(n_expr, cmp_bound, "strncmp")?;

        let func = self.current_function("compile strncmp length branch")?;
        let zero_b = self.context.append_basic_block(func, "strncmp_len_zero");
        let nz_b = self.context.append_basic_block(func, "strncmp_len_nz");
        let final_b = self.context.append_basic_block(func, "strncmp_len_cont");
        self.builder
            .build_conditional_branch(len_is_zero, zero_b, nz_b)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder.position_at_end(zero_b);
        let bool_true = self.context.bool_type().const_int(1, false);
        self.builder
            .build_unconditional_branch(final_b)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let zero_block = self.current_insert_block("finish strncmp zero-length block")?;

        self.builder.position_at_end(nz_b);

        let (arr_ty, buf_global) = self.get_or_create_i8_buffer(cmp_bound, "_gs_bi_strncmp");
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let dst_ptr = self
            .builder
            .build_bit_cast(buf_global, ptr_ty, "strncmp_dst_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let base_src_ptr = self
            .builder
            .build_int_to_ptr(ptr_i64.value, ptr_ty, "strncmp_src_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let src_ptr = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                ptr_i64.offsets_found,
                base_src_ptr.into(),
                ptr_ty.const_null().into(),
                "strncmp_src_or_null",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_pointer_value();
        let effective_len = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                ptr_i64.offsets_found,
                bounded_len.into(),
                self.context.i32_type().const_zero().into(),
                "strncmp_len_or_zero",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let ret = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[dst_ptr, effective_len.into(), src_ptr.into()],
                self.context.i64_type().into(),
                "probe_read_user_strncmp",
            )?
            .into_int_value();
        let read_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                ret,
                self.context.i64_type().const_zero(),
                "rd_ok",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let status_ok = self
            .builder
            .build_and(read_ok, ptr_i64.offsets_found, "strncmp_ok_with_offsets")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // If in condition context and read failed, set condition error code = 1 (ProbeReadFailed)
        if self.condition_context_active {
            let func = self.current_function("compile strncmp condition error branch")?;
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
            let _ = self.set_condition_error_addr_if_unset(ptr_i64.value);
            // flags: bit0 = read failure for strncmp
            let one = self.context.i8_type().const_int(1, false);
            let _ = self.or_condition_error_flags(one);
            self.builder
                .build_unconditional_branch(cont_b)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(cont_b);
        }

        // XOR/OR accumulation over the bounded maximum; inactive bytes do not contribute.
        let i32_ty = self.context.i32_type();
        let idx0 = i32_ty.const_zero();
        let mut acc = self.context.i8_type().const_zero();
        for (i, b) in lit.as_bytes().iter().take(cmp_bound as usize).enumerate() {
            let idx_i = i32_ty.const_int(i as u64, false);
            // SAFETY: i is bounded by cmp_bound, which is clamped to the buffer cap.
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
            let active = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGT,
                    bounded_len,
                    idx_i,
                    "strncmp_byte_active",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let diff = self
                .builder
                .build_select(
                    active,
                    diff,
                    self.context.i8_type().const_zero(),
                    "strncmp_active_diff",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                .into_int_value();
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
        self.builder
            .build_unconditional_branch(final_b)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let nz_block = self.current_insert_block("finish strncmp non-zero block")?;

        self.builder.position_at_end(final_b);
        let result_phi = self
            .builder
            .build_phi(self.context.bool_type(), "strncmp_result")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        result_phi.add_incoming(&[(&bool_true, zero_block), (&result, nz_block)]);
        Ok(result_phi.as_basic_value())
    }

    /// Compile comparison between a DWARF-side expression and a script string literal.
    /// Supports char* and char[N] according to design in string_comparison.md.
    pub(super) fn compile_string_comparison(
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

        let lit_bytes = lit.as_bytes();
        let lit_len = lit_bytes.len() as u32;
        let one = self.context.bool_type().const_int(1, false);
        let zero = self.context.bool_type().const_zero();

        // Build final boolean accumulator
        let result = match dwarf_type_opt.map(ghostscope_dwarf::strip_type_aliases) {
            // char* / const char*
            Some(TI::PointerType { target_type, .. }) => {
                // Ensure pointee is char-like
                let base = ghostscope_dwarf::strip_type_aliases(target_type.as_ref());
                let is_char_like = matches!(base, TI::BaseType { name, size, .. } if name.contains("char") && *size == 1);
                if !is_char_like {
                    return Err(CodeGenError::TypeError(
                        "automatic string comparison only supports char*".into(),
                    ));
                }

                // Evaluate expression to pointer value and read up to L+1 bytes
                let pc_address = self.get_compile_time_context()?.pc_address;
                let val_any = self.variable_read_plan_to_llvm_value(&var, pc_address, None)?;
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
                let (buf_global, ret_len, arr_ty) = self.read_user_cstr_into_buffer(
                    RuntimeAddress::available(ptr_i64, self.context),
                    need,
                    "_gs_strbuf",
                )?;

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
                // SAFETY: the string read requested lit_len + 1 bytes, so index
                // lit_len is within the scratch buffer.
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
                    // SAFETY: lit_bytes length is bounded by the scratch buffer size.
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
                let elem = ghostscope_dwarf::strip_type_aliases(element_type.as_ref());
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
                let status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    None
                };
                let pc_address = self.get_compile_time_context()?.pc_address;
                let addr =
                    self.variable_read_plan_to_runtime_address(&var, pc_address, status_ptr)?;
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
                // SAFETY: the string read requested lit_len + 1 bytes, so index
                // lit_len is within the scratch buffer.
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
                    // SAFETY: lit_bytes length is bounded by the scratch buffer size.
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
                let status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    None
                };
                let pc_address = self.get_compile_time_context()?.pc_address;
                let addr =
                    self.variable_read_plan_to_runtime_address(&var, pc_address, status_ptr)?;
                // Fallback using type_name string
                match parse_type_name(&var.type_name) {
                    ParsedKind::PtrChar => {
                        // Load pointer value from variable location (assume 64-bit)
                        let ptr_any = self.generate_memory_read(
                            addr,
                            ghostscope_dwarf::MemoryAccessSize::U64,
                            None,
                        )?;
                        let ptr_i64 = match ptr_any {
                            BasicValueEnum::IntValue(iv) => iv,
                            _ => {
                                return Err(CodeGenError::LLVMError(
                                    "pointer load did not return integer".to_string(),
                                ))
                            }
                        };
                        let need = lit_len + 1;
                        let (buf_global, ret_len, arr_ty) = self.read_user_cstr_into_buffer(
                            RuntimeAddress::available(ptr_i64, self.context),
                            need,
                            "_gs_strbuf",
                        )?;

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
                        // SAFETY: the string read requested lit_len + 1 bytes, so
                        // index lit_len is within the scratch buffer.
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
                            // SAFETY: lit_bytes length is bounded by the scratch buffer size.
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
                        // SAFETY: the string read requested lit_len + 1 bytes, so
                        // index lit_len is within the scratch buffer.
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
                            // SAFETY: lit_bytes length is bounded by the scratch buffer size.
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

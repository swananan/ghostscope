use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn lookup_proc_module_range_meta(
        &mut self,
        pid: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtModuleRangeMeta<'ctx>> {
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("proc_module_range_meta")
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_range_meta map not found".to_string())
            })?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                &format!("{name_prefix}_meta_map_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let key_arr_ty = i32_type.array_type(4);
        let zero = i32_type.const_zero();
        // SAFETY: key_alloca is the [4 x i32] pm_key stack slot and [0, 0]
        // addresses the pid key element for proc_module_range_meta.
        let key_ptr = unsafe {
            self.builder
                .build_gep(
                    key_arr_ty,
                    key_alloca,
                    &[zero, zero],
                    &format!("{name_prefix}_meta_key_ptr"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(key_ptr, pid)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_arg = self
            .builder
            .build_bit_cast(key_ptr, ptr_type, &format!("{name_prefix}_meta_key_arg"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let lookup_id = i64_type.const_int(BPF_FUNC_map_lookup_elem as u64, false);
        let lookup_fn_type = ptr_type.fn_type(&[ptr_type.into(), ptr_type.into()], false);
        let lookup_fn_ptr = self
            .builder
            .build_int_to_ptr(
                lookup_id,
                ptr_type,
                &format!("{name_prefix}_meta_lookup_fn"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let args: Vec<BasicMetadataValueEnum> = vec![map_ptr.into(), key_arg.into()];
        let value_ptr_any = self
            .builder
            .build_indirect_call(
                lookup_fn_type,
                lookup_fn_ptr,
                &args,
                &format!("{name_prefix}_meta_lookup"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_range_meta lookup returned void".to_string())
            })?;
        let value_ptr = match value_ptr_any {
            BasicValueEnum::PointerValue(p) => p,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "proc_module_range_meta lookup did not return pointer".to_string(),
                ));
            }
        };
        let current_fn = self.current_function("lookup proc module range meta")?;
        let hit_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_meta_hit"));
        let miss_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_meta_miss"));
        let cont_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_meta_cont"));
        let value_ptr_int = self
            .builder
            .build_ptr_to_int(
                value_ptr,
                i64_type,
                &format!("{name_prefix}_meta_value_ptr_int"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_hit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                value_ptr_int,
                i64_type.const_zero(),
                &format!("{name_prefix}_meta_found"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_hit, hit_block, miss_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(hit_block);
        let load_i32_field = |offset: usize, field_name: &str, ctx: &mut EbpfContext<'ctx, 'dw>| {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: value_ptr points at ProcModuleRangeMeta returned by
            // bpf_map_lookup_elem and offset is an i32 field offset.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), value_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_load(ctx.context.i32_type(), field_ptr, field_name)
                .map(|value| value.into_int_value())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        let active_slot = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_META_ACTIVE_SLOT_OFFSET,
            &format!("{name_prefix}_meta_active_slot"),
            self,
        )?;
        let count = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_META_COUNT_OFFSET,
            &format!("{name_prefix}_meta_count"),
            self,
        )?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let hit_end = self.current_insert_block("finish module range meta hit block")?;

        self.builder.position_at_end(miss_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let miss_end = self.current_insert_block("finish module range meta miss block")?;

        self.builder.position_at_end(cont_block);
        let found_type = self.context.bool_type();
        let found_phi = self
            .builder
            .build_phi(found_type, &format!("{name_prefix}_meta_found_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        found_phi.add_incoming(&[
            (&found_type.const_int(1, false), hit_end),
            (&found_type.const_zero(), miss_end),
        ]);
        let phi_i32 = |ctx: &mut EbpfContext<'ctx, 'dw>, name: &str, hit_value: IntValue<'ctx>| {
            let phi = ctx
                .builder
                .build_phi(ctx.context.i32_type(), name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            phi.add_incoming(&[
                (&hit_value, hit_end),
                (&ctx.context.i32_type().const_zero(), miss_end),
            ]);
            Ok::<_, CodeGenError>(phi.as_basic_value().into_int_value())
        };
        Ok(BtModuleRangeMeta {
            found: found_phi.as_basic_value().into_int_value(),
            active_slot: phi_i32(self, &format!("{name_prefix}_meta_slot_phi"), active_slot)?,
            count: phi_i32(self, &format!("{name_prefix}_meta_count_phi"), count)?,
        })
    }

    pub(super) fn lookup_proc_module_range_value(
        &mut self,
        pid: IntValue<'ctx>,
        slot: IntValue<'ctx>,
        index: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtModuleRangeValue<'ctx>> {
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("proc_module_ranges")
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_ranges map not found".to_string())
            })?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                &format!("{name_prefix}_range_map_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        self.builder
            .build_store(key_alloca, i32_type.array_type(4).const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let store_key_u32 = |offset: usize,
                             value: IntValue<'ctx>,
                             field_name: &str,
                             ctx: &mut EbpfContext<'ctx, 'dw>|
         -> Result<()> {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: key_alloca is the ProcModuleRangeKey stack slot and
            // offset is one of its u32 field offsets.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), key_alloca, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_store(field_ptr, value)
                .map(|_| ())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_PID_OFFSET,
            pid,
            &format!("{name_prefix}_range_key_pid"),
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_SLOT_OFFSET,
            slot,
            &format!("{name_prefix}_range_key_slot"),
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_INDEX_OFFSET,
            index,
            &format!("{name_prefix}_range_key_index"),
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_PAD_OFFSET,
            i32_type.const_zero(),
            &format!("{name_prefix}_range_key_pad"),
            self,
        )?;
        let key_arg = self
            .builder
            .build_bit_cast(
                key_alloca,
                ptr_type,
                &format!("{name_prefix}_range_key_arg"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let lookup_id = i64_type.const_int(BPF_FUNC_map_lookup_elem as u64, false);
        let lookup_fn_type = ptr_type.fn_type(&[ptr_type.into(), ptr_type.into()], false);
        let lookup_fn_ptr = self
            .builder
            .build_int_to_ptr(
                lookup_id,
                ptr_type,
                &format!("{name_prefix}_range_lookup_fn"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let args: Vec<BasicMetadataValueEnum> = vec![map_ptr.into(), key_arg.into()];
        let value_ptr_any = self
            .builder
            .build_indirect_call(
                lookup_fn_type,
                lookup_fn_ptr,
                &args,
                &format!("{name_prefix}_range_lookup"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_ranges lookup returned void".to_string())
            })?;
        let value_ptr = match value_ptr_any {
            BasicValueEnum::PointerValue(p) => p,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "proc_module_ranges lookup did not return pointer".to_string(),
                ));
            }
        };
        let current_fn = self.current_function("lookup proc module range value")?;
        let hit_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_range_hit"));
        let miss_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_range_miss"));
        let cont_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_range_cont"));
        let value_ptr_int = self
            .builder
            .build_ptr_to_int(
                value_ptr,
                i64_type,
                &format!("{name_prefix}_range_value_ptr_int"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_hit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                value_ptr_int,
                i64_type.const_zero(),
                &format!("{name_prefix}_range_found"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_hit, hit_block, miss_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(hit_block);
        let load_i64_field = |offset: usize, field_name: &str, ctx: &mut EbpfContext<'ctx, 'dw>| {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: value_ptr points at ProcModuleRangeValue returned by
            // bpf_map_lookup_elem and offset is a u64 field offset.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), value_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_load(ctx.context.i64_type(), field_ptr, field_name)
                .map(|value| value.into_int_value())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        let load_i32_field = |offset: usize, field_name: &str, ctx: &mut EbpfContext<'ctx, 'dw>| {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: value_ptr points at ProcModuleRangeValue returned by
            // bpf_map_lookup_elem and offset is a u32 field offset.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), value_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_load(ctx.context.i32_type(), field_ptr, field_name)
                .map(|value| value.into_int_value())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        let base = load_i64_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_BASE_OFFSET,
            &format!("{name_prefix}_range_base"),
            self,
        )?;
        let end = load_i64_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_END_OFFSET,
            &format!("{name_prefix}_range_end"),
            self,
        )?;
        let text = load_i64_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_TEXT_OFFSET,
            &format!("{name_prefix}_range_text"),
            self,
        )?;
        let cookie_lo = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_COOKIE_LO_OFFSET,
            &format!("{name_prefix}_range_cookie_lo"),
            self,
        )?;
        let cookie_hi = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_COOKIE_HI_OFFSET,
            &format!("{name_prefix}_range_cookie_hi"),
            self,
        )?;
        let cookie_lo64 = self
            .builder
            .build_int_z_extend(cookie_lo, i64_type, &format!("{name_prefix}_cookie_lo64"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cookie_hi64 = self
            .builder
            .build_int_z_extend(cookie_hi, i64_type, &format!("{name_prefix}_cookie_hi64"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cookie_hi_shifted = self
            .builder
            .build_left_shift(
                cookie_hi64,
                i64_type.const_int(32, false),
                &format!("{name_prefix}_cookie_hi_shift"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cookie = self
            .builder
            .build_or(
                cookie_lo64,
                cookie_hi_shifted,
                &format!("{name_prefix}_cookie"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let hit_end = self.current_insert_block("finish module range value hit block")?;

        self.builder.position_at_end(miss_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let miss_end = self.current_insert_block("finish module range value miss block")?;

        self.builder.position_at_end(cont_block);
        let zero_i64 = i64_type.const_zero();
        let found_type = self.context.bool_type();
        let found_phi = self
            .builder
            .build_phi(found_type, &format!("{name_prefix}_range_found_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        found_phi.add_incoming(&[
            (&found_type.const_int(1, false), hit_end),
            (&found_type.const_zero(), miss_end),
        ]);
        let phi_i64 = |ctx: &mut EbpfContext<'ctx, 'dw>, name: &str, hit_value: IntValue<'ctx>| {
            let phi = ctx
                .builder
                .build_phi(ctx.context.i64_type(), name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            phi.add_incoming(&[(&hit_value, hit_end), (&zero_i64, miss_end)]);
            Ok::<_, CodeGenError>(phi.as_basic_value().into_int_value())
        };
        Ok(BtModuleRangeValue {
            found: found_phi.as_basic_value().into_int_value(),
            base: phi_i64(self, &format!("{name_prefix}_range_base_phi"), base)?,
            end: phi_i64(self, &format!("{name_prefix}_range_end_phi"), end)?,
            text: phi_i64(self, &format!("{name_prefix}_range_text_phi"), text)?,
            cookie: phi_i64(self, &format!("{name_prefix}_range_cookie_phi"), cookie)?,
        })
    }

    pub(super) fn lookup_backtrace_frame_module_in_ranges(
        &mut self,
        raw_ip: IntValue<'ctx>,
        pid: IntValue<'ctx>,
        meta: BtModuleRangeMeta<'ctx>,
        fallback_cookie: IntValue<'ctx>,
        fallback_bias: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtFrameModule<'ctx>> {
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let bool_type = self.context.bool_type();
        let max_steps = backtrace_row_binary_search_steps(
            (self.compile_options.proc_module_offsets_max_entries as usize).saturating_mul(2),
        );
        let current_fn = self.current_function("lookup backtrace frame module")?;

        let mut found = bool_type.const_zero();
        let mut cookie = fallback_cookie;
        let mut bias = fallback_bias;
        let mut lo = i32_type.const_zero();
        let mut hi = meta.count;

        for step in 0..max_steps {
            let not_found = self
                .builder
                .build_not(found, &format!("{name_prefix}_{step}_not_found"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let range_active = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    lo,
                    hi,
                    &format!("{name_prefix}_{step}_active"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let pending = self
                .builder
                .build_and(
                    not_found,
                    range_active,
                    &format!("{name_prefix}_{step}_pending"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let should_search = self
                .builder
                .build_and(
                    pending,
                    meta.found,
                    &format!("{name_prefix}_{step}_should_search"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let search_block = self
                .context
                .append_basic_block(current_fn, &format!("{name_prefix}_{step}_search"));
            let skip_block = self
                .context
                .append_basic_block(current_fn, &format!("{name_prefix}_{step}_skip"));
            let after_block = self
                .context
                .append_basic_block(current_fn, &format!("{name_prefix}_{step}_after"));
            self.builder
                .build_conditional_branch(should_search, search_block, skip_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(skip_block);
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let skip_end = self.current_insert_block("finish module range skip block")?;

            self.builder.position_at_end(search_block);
            let lo_plus_hi = self
                .builder
                .build_int_add(lo, hi, &format!("{name_prefix}_{step}_lo_plus_hi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let mid = self
                .builder
                .build_right_shift(
                    lo_plus_hi,
                    i32_type.const_int(1, false),
                    false,
                    &format!("{name_prefix}_{step}_mid"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let range = self.lookup_proc_module_range_value(
                pid,
                meta.active_slot,
                mid,
                &format!("{name_prefix}_{step}"),
            )?;
            let at_or_after_base = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGE,
                    raw_ip,
                    range.base,
                    &format!("{name_prefix}_{step}_after_base"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let before_end = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    raw_ip,
                    range.end,
                    &format!("{name_prefix}_{step}_before_end"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let in_bounds = self
                .builder
                .build_and(
                    at_or_after_base,
                    before_end,
                    &format!("{name_prefix}_{step}_in_bounds"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let in_range = self
                .builder
                .build_and(
                    range.found,
                    in_bounds,
                    &format!("{name_prefix}_{step}_in_range"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let before_range = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    raw_ip,
                    range.base,
                    &format!("{name_prefix}_{step}_before_range"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let after_range = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGE,
                    raw_ip,
                    range.end,
                    &format!("{name_prefix}_{step}_after_range"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let found_next = self
                .builder
                .build_or(found, in_range, &format!("{name_prefix}_{step}_found_next"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let selected_cookie = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    in_range,
                    range.cookie.into(),
                    cookie.into(),
                    &format!("{name_prefix}_{step}_selected_cookie"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let selected_bias = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    in_range,
                    range.text.into(),
                    bias.into(),
                    &format!("{name_prefix}_{step}_selected_bias"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let mid_plus_one = self
                .builder
                .build_int_add(
                    mid,
                    i32_type.const_int(1, false),
                    &format!("{name_prefix}_{step}_mid_plus_one"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let range_missing = self
                .builder
                .build_not(range.found, &format!("{name_prefix}_{step}_range_missing"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let hi_next = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    before_range,
                    mid.into(),
                    hi.into(),
                    &format!("{name_prefix}_{step}_hi_next"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let lo_after = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    after_range,
                    mid_plus_one.into(),
                    lo.into(),
                    &format!("{name_prefix}_{step}_lo_after"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let lo_next = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    range_missing,
                    hi.into(),
                    lo_after.into(),
                    &format!("{name_prefix}_{step}_lo_next"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let search_end = self.current_insert_block("finish module range search block")?;

            self.builder.position_at_end(after_block);

            let found_phi = self
                .builder
                .build_phi(bool_type, &format!("{name_prefix}_{step}_found_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            found_phi.add_incoming(&[(&found_next, search_end), (&found, skip_end)]);
            found = found_phi.as_basic_value().into_int_value();

            let cookie_phi = self
                .builder
                .build_phi(i64_type, &format!("{name_prefix}_{step}_cookie_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            cookie_phi.add_incoming(&[(&selected_cookie, search_end), (&cookie, skip_end)]);
            cookie = cookie_phi.as_basic_value().into_int_value();

            let bias_phi = self
                .builder
                .build_phi(i64_type, &format!("{name_prefix}_{step}_bias_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            bias_phi.add_incoming(&[(&selected_bias, search_end), (&bias, skip_end)]);
            bias = bias_phi.as_basic_value().into_int_value();

            let lo_phi = self
                .builder
                .build_phi(i32_type, &format!("{name_prefix}_{step}_lo_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            lo_phi.add_incoming(&[(&lo_next, search_end), (&lo, skip_end)]);
            lo = lo_phi.as_basic_value().into_int_value();

            let hi_phi = self
                .builder
                .build_phi(i32_type, &format!("{name_prefix}_{step}_hi_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            hi_phi.add_incoming(&[(&hi_next, search_end), (&hi, skip_end)]);
            hi = hi_phi.as_basic_value().into_int_value();
        }

        Ok(BtFrameModule {
            cookie,
            bias,
            found,
        })
    }

    pub(super) fn resolve_backtrace_frame_module(
        &mut self,
        raw_ip: IntValue<'ctx>,
        fallback_cookie: IntValue<'ctx>,
        fallback_bias: IntValue<'ctx>,
        fallback_found: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtFrameModule<'ctx>> {
        if self.backtrace_module_row_ranges.is_empty() {
            return Ok(BtFrameModule {
                cookie: fallback_cookie,
                bias: fallback_bias,
                found: fallback_found,
            });
        }

        let pid = self.proc_module_pid_key(name_prefix)?;
        let meta = self.lookup_proc_module_range_meta(pid, name_prefix)?;
        self.lookup_backtrace_frame_module_in_ranges(
            raw_ip,
            pid,
            meta,
            fallback_cookie,
            fallback_bias,
            name_prefix,
        )
    }

    pub(super) fn backtrace_module_fallback_found(&self, found: IntValue<'ctx>) -> IntValue<'ctx> {
        if self.backtrace_module_row_ranges.is_empty() {
            found
        } else {
            self.context.bool_type().const_zero()
        }
    }

    pub(super) fn backtrace_lookup_pc_from_raw(
        &self,
        raw_ip: IntValue<'ctx>,
        module_bias: IntValue<'ctx>,
        offsets_found: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        self.normalized_pc_from_raw(raw_ip, module_bias, offsets_found)
    }
}

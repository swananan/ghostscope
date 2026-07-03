use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn compact_unwind_row_for_backtrace(
        &self,
        module_path: &str,
        pc: u64,
    ) -> Option<CompactUnwindRow> {
        let analyzer = self.process_analyzer?;
        let module_address = ModuleAddress::new(PathBuf::from(module_path), pc);
        let ctx = analyzer.resolve_pc(&module_address).ok()?;
        analyzer.compact_unwind_row_for_context(&ctx).ok().flatten()
    }

    pub(super) fn usable_backtrace_unwind_row_for_pc(
        &self,
        module_path: &str,
        pc: u64,
    ) -> BacktraceUnwindRowForPc {
        let Some(row) = self.compact_unwind_row_for_backtrace(module_path, pc) else {
            return BacktraceUnwindRowForPc::Missing;
        };
        match crate::backtrace_unwind_row_from_compact(&row) {
            Some(row) => BacktraceUnwindRowForPc::Usable(row),
            None => BacktraceUnwindRowForPc::Unsupported,
        }
    }

    pub(super) fn status_for_backtrace_unwind_row_for_pc(
        &self,
        row: &BacktraceUnwindRowForPc,
    ) -> BacktraceStatus {
        match row {
            BacktraceUnwindRowForPc::Usable(_) => BacktraceStatus::ReadError,
            BacktraceUnwindRowForPc::Missing if self.process_analyzer.is_some() => {
                BacktraceStatus::NoUnwindRowsForPc
            }
            BacktraceUnwindRowForPc::Unsupported if self.process_analyzer.is_some() => {
                BacktraceStatus::UnsupportedCfi
            }
            BacktraceUnwindRowForPc::Missing | BacktraceUnwindRowForPc::Unsupported => {
                BacktraceStatus::DwarfUnavailable
            }
        }
    }

    pub(super) fn runtime_row_from_static(
        &self,
        row: ghostscope_protocol::BacktraceUnwindRow,
    ) -> RuntimeBtUnwindRow<'ctx> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let i64_type = self.context.i64_type();
        RuntimeBtUnwindRow {
            found: self.context.bool_type().const_int(1, false),
            cfa_register: i16_type.const_int(row.cfa_register as u64, false),
            cfa_offset: i64_type.const_int(row.cfa_offset as u64, true),
            ra_kind: i8_type.const_int(row.ra_kind as u64, false),
            ra_register: i16_type.const_int(row.ra_register as u64, false),
            ra_offset: i64_type.const_int(row.ra_offset as u64, true),
            rbp_kind: i8_type.const_int(row.rbp_kind as u64, false),
            rbp_register: i16_type.const_int(row.rbp_register as u64, false),
            rbp_offset: i64_type.const_int(row.rbp_offset as u64, true),
        }
    }

    pub(super) fn allocate_backtrace_scratch(&self) -> Result<BtScratch<'ctx>> {
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();

        Ok(BtScratch {
            row: RuntimeBtRowScratch {
                found_ptr: self.build_entry_alloca(i32_type, "bt_row_found")?,
                cfa_register_ptr: self.build_entry_alloca(i16_type, "bt_row_cfa_register")?,
                cfa_offset_ptr: self.build_entry_alloca(i64_type, "bt_row_cfa_offset")?,
                ra_kind_ptr: self.build_entry_alloca(self.context.i8_type(), "bt_row_ra_kind")?,
                ra_register_ptr: self.build_entry_alloca(i16_type, "bt_row_ra_register")?,
                ra_offset_ptr: self.build_entry_alloca(i64_type, "bt_row_ra_offset")?,
                rbp_kind_ptr: self.build_entry_alloca(self.context.i8_type(), "bt_row_rbp_kind")?,
                rbp_register_ptr: self.build_entry_alloca(i16_type, "bt_row_rbp_register")?,
                rbp_offset_ptr: self.build_entry_alloca(i64_type, "bt_row_rbp_offset")?,
            },
            next_rbp_ptr: self.build_entry_alloca(i64_type, "bt_next_rbp")?,
            next_error_code_ptr: self.build_entry_alloca(i16_type, "bt_next_error_code")?,
        })
    }

    pub(super) fn lookup_backtrace_unwind_row(
        &mut self,
        normalized_pc: IntValue<'ctx>,
        module_cookie: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
        name_prefix: &str,
    ) -> Result<RuntimeBtUnwindRow<'ctx>> {
        let bounds = self.backtrace_unwind_row_bounds_for_module(module_cookie, name_prefix)?;
        self.lookup_backtrace_unwind_row_in_range(normalized_pc, bounds.start, bounds.end, scratch)
    }

    pub(super) fn backtrace_unwind_row_bounds_for_module(
        &mut self,
        module_cookie: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtRowBounds<'ctx>> {
        let i32_type = self.context.i32_type();
        if self.backtrace_module_row_ranges.is_empty() {
            return Ok(BtRowBounds {
                start: i32_type.const_zero(),
                end: i32_type.const_int(self.backtrace_unwind_rows.len() as u64, false),
            });
        }

        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("bt_module_row_ranges")
            .ok_or_else(|| {
                CodeGenError::LLVMError("bt_module_row_ranges map not found".to_string())
            })?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                &format!("{name_prefix}_row_ranges_map_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca =
            self.build_entry_alloca(i64_type, &format!("{name_prefix}_row_range_key"))?;
        self.builder
            .build_store(key_alloca, module_cookie)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_ptr = self
            .builder
            .build_bit_cast(
                key_alloca,
                ptr_type,
                &format!("{name_prefix}_row_range_key_void"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let result = self.create_bpf_helper_call(
            BPF_FUNC_map_lookup_elem as u64,
            &[map_ptr, key_ptr],
            ptr_type.into(),
            &format!("{name_prefix}_row_range_lookup"),
        )?;
        let range_ptr = match result {
            BasicValueEnum::PointerValue(ptr) => ptr,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "bt_module_row_ranges lookup did not return pointer".to_string(),
                ))
            }
        };
        let is_null = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                self.builder
                    .build_ptr_to_int(
                        range_ptr,
                        i64_type,
                        &format!("{name_prefix}_row_range_ptr_i64"),
                    )
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
                i64_type.const_zero(),
                &format!("{name_prefix}_row_range_is_null"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let current_fn = self.current_function("lookup bt row range")?;
        let found_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_found_row_range"));
        let miss_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_miss_row_range"));
        let cont_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_cont_row_range"));
        self.builder
            .build_conditional_branch(is_null, miss_block, found_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(found_block);
        let load_range_field = |offset: usize,
                                field_name: &str,
                                ctx: &mut EbpfContext<'ctx, 'dw>|
         -> Result<IntValue<'ctx>> {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: range_ptr is a non-null BacktraceModuleRowRange pointer
            // returned by bpf_map_lookup_elem, and offsets are shared ABI
            // constants from ghostscope-protocol.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), range_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            Ok(ctx
                .builder
                .build_load(ctx.context.i32_type(), field_ptr, field_name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value())
        };
        let found_start = load_range_field(
            ghostscope_protocol::BACKTRACE_MODULE_ROW_RANGE_ROW_START_OFFSET,
            &format!("{name_prefix}_row_range_start"),
            self,
        )?;
        let found_end = load_range_field(
            ghostscope_protocol::BACKTRACE_MODULE_ROW_RANGE_ROW_END_OFFSET,
            &format!("{name_prefix}_row_range_end"),
            self,
        )?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let found_end_block = self.current_insert_block("finish bt row range found block")?;

        self.builder.position_at_end(miss_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let miss_end_block = self.current_insert_block("finish bt row range miss block")?;

        self.builder.position_at_end(cont_block);
        let start_phi = self
            .builder
            .build_phi(i32_type, &format!("{name_prefix}_row_start_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        start_phi.add_incoming(&[
            (&found_start, found_end_block),
            (&i32_type.const_zero(), miss_end_block),
        ]);
        let end_phi = self
            .builder
            .build_phi(i32_type, &format!("{name_prefix}_row_end_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        end_phi.add_incoming(&[
            (&found_end, found_end_block),
            (&i32_type.const_zero(), miss_end_block),
        ]);

        Ok(BtRowBounds {
            start: start_phi.as_basic_value().into_int_value(),
            end: end_phi.as_basic_value().into_int_value(),
        })
    }

    pub(super) fn lookup_backtrace_unwind_row_in_range(
        &mut self,
        normalized_pc: IntValue<'ctx>,
        row_start: IntValue<'ctx>,
        row_end: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
    ) -> Result<RuntimeBtUnwindRow<'ctx>> {
        let row_count = self.backtrace_unwind_row_map_entries() as usize;
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let i8_type = self.context.i8_type();
        let sentinel = i32_type.const_int(row_count as u64, false);

        self.builder
            .build_store(scratch.found_ptr, sentinel)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.cfa_register_ptr, i16_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.cfa_offset_ptr, i64_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_kind_ptr, i8_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_register_ptr, i16_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_offset_ptr, i64_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_kind_ptr, i8_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_register_ptr, i16_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_offset_ptr, i64_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let current_fn = self.current_function("lookup bt unwind row")?;
        let return_block = self
            .context
            .append_basic_block(current_fn, "bt_row_lookup_return");
        if row_count == 0 {
            self.builder
                .build_unconditional_branch(return_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        } else {
            let lo_ptr = self.build_entry_alloca(i32_type, "bt_row_lo")?;
            let hi_ptr = self.build_entry_alloca(i32_type, "bt_row_hi")?;
            self.builder
                .build_store(lo_ptr, row_start)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(hi_ptr, row_end)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.emit_backtrace_row_runtime_binary_search(
                normalized_pc,
                scratch,
                lo_ptr,
                hi_ptr,
                row_count,
                return_block,
            )?;
        }
        self.builder.position_at_end(return_block);
        let final_found_idx = self.load_i32(scratch.found_ptr, "bt_final_found_idx")?;
        let found = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                final_found_idx,
                sentinel,
                "bt_final_row_found",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(RuntimeBtUnwindRow {
            found,
            cfa_register: self.load_i16(scratch.cfa_register_ptr, "bt_final_cfa_reg")?,
            cfa_offset: self.load_i64(scratch.cfa_offset_ptr, "bt_final_cfa_off")?,
            ra_kind: self.load_i8(scratch.ra_kind_ptr, "bt_final_ra_kind")?,
            ra_register: self.load_i16(scratch.ra_register_ptr, "bt_final_ra_reg")?,
            ra_offset: self.load_i64(scratch.ra_offset_ptr, "bt_final_ra_off")?,
            rbp_kind: self.load_i8(scratch.rbp_kind_ptr, "bt_final_rbp_kind")?,
            rbp_register: self.load_i16(scratch.rbp_register_ptr, "bt_final_rbp_reg")?,
            rbp_offset: self.load_i64(scratch.rbp_offset_ptr, "bt_final_rbp_off")?,
        })
    }

    pub(super) fn emit_backtrace_row_runtime_binary_search(
        &mut self,
        normalized_pc: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
        lo_ptr: PointerValue<'ctx>,
        hi_ptr: PointerValue<'ctx>,
        row_count: usize,
        return_block: BasicBlock<'ctx>,
    ) -> Result<()> {
        let current_fn = self.current_function("emit bt row lookup tree")?;
        let i32_type = self.context.i32_type();
        let sentinel = i32_type.const_int(row_count as u64, false);
        let max_steps = backtrace_row_binary_search_steps(row_count);

        for _ in 0..max_steps {
            let found_idx = self.load_i32(scratch.found_ptr, "bt_lookup_found_idx")?;
            let not_found = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    found_idx,
                    sentinel,
                    "bt_lookup_not_found",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let lo = self.load_i32(lo_ptr, "bt_lookup_lo")?;
            let hi = self.load_i32(hi_ptr, "bt_lookup_hi")?;
            let range_active = self
                .builder
                .build_int_compare(inkwell::IntPredicate::ULT, lo, hi, "bt_lookup_range_active")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let should_search = self
                .builder
                .build_and(not_found, range_active, "bt_lookup_should_search")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            let search_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_search");
            let skip_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_skip");
            let after_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_after");
            self.builder
                .build_conditional_branch(should_search, search_block, skip_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(skip_block);
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(search_block);
            let lo_plus_hi = self
                .builder
                .build_int_add(lo, hi, "bt_lookup_lo_plus_hi")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let mid = self
                .builder
                .build_right_shift(
                    lo_plus_hi,
                    i32_type.const_int(1, false),
                    false,
                    "bt_lookup_mid",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let row_ptr = self.lookup_bt_unwind_row_ptr(mid)?;
            let row_is_null = self
                .builder
                .build_is_null(row_ptr, "bt_lookup_row_is_null")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let row_null_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_row_null");
            let row_load_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_row_load");
            self.builder
                .build_conditional_branch(row_is_null, row_null_block, row_load_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(row_null_block);
            self.builder
                .build_store(lo_ptr, hi)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(row_load_block);
            let pc_start = self.load_row_i64(
                row_ptr,
                crate::BACKTRACE_UNWIND_ROW_PC_START_OFFSET,
                "bt_lookup_row_pc_start",
            )?;
            let pc_end = self.load_row_i64(
                row_ptr,
                crate::BACKTRACE_UNWIND_ROW_PC_END_OFFSET,
                "bt_lookup_row_pc_end",
            )?;
            let before = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    normalized_pc,
                    pc_start,
                    "bt_lookup_pc_before",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let before_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_before");
            let not_before_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_not_before");
            self.builder
                .build_conditional_branch(before, before_block, not_before_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(before_block);
            self.builder
                .build_store(hi_ptr, mid)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(not_before_block);
            let after = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGE,
                    normalized_pc,
                    pc_end,
                    "bt_lookup_pc_after",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let after_range_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_after_range");
            let match_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_match");
            self.builder
                .build_conditional_branch(after, after_range_block, match_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(after_range_block);
            let mid_plus_one = self
                .builder
                .build_int_add(mid, i32_type.const_int(1, false), "bt_lookup_mid_plus_one")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(lo_ptr, mid_plus_one)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(match_block);
            self.store_backtrace_unwind_row_from_ptr(row_ptr, mid, scratch)?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(after_block);
        }

        self.builder
            .build_unconditional_branch(return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(super) fn store_backtrace_unwind_row_from_ptr(
        &self,
        row_ptr: PointerValue<'ctx>,
        row_index: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
    ) -> Result<()> {
        self.builder
            .build_store(scratch.found_ptr, row_index)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_register = self.load_row_i16(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_CFA_REGISTER_OFFSET,
            "bt_tree_row_cfa_reg",
        )?;
        let cfa_offset = self.load_row_i64(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_CFA_OFFSET_OFFSET,
            "bt_tree_row_cfa_off",
        )?;
        let ra_kind = self.load_row_i8(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RA_KIND_OFFSET,
            "bt_tree_row_ra_kind",
        )?;
        let ra_register = self.load_row_i16(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RA_REGISTER_OFFSET,
            "bt_tree_row_ra_reg",
        )?;
        let ra_offset = self.load_row_i64(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RA_OFFSET_OFFSET,
            "bt_tree_row_ra_off",
        )?;
        let rbp_kind = self.load_row_i8(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RBP_KIND_OFFSET,
            "bt_tree_row_rbp_kind",
        )?;
        let rbp_register = self.load_row_i16(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RBP_REGISTER_OFFSET,
            "bt_tree_row_rbp_reg",
        )?;
        let rbp_offset = self.load_row_i64(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RBP_OFFSET_OFFSET,
            "bt_tree_row_rbp_off",
        )?;
        self.builder
            .build_store(scratch.cfa_register_ptr, cfa_register)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.cfa_offset_ptr, cfa_offset)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_kind_ptr, ra_kind)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_register_ptr, ra_register)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_offset_ptr, ra_offset)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_kind_ptr, rbp_kind)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_register_ptr, rbp_register)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_offset_ptr, rbp_offset)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }
}

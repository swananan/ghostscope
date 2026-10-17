use super::context::{CodeGenError, EbpfContext, Result};
use ghostscope_dwarf::{
    MemoryAccessSize, PlannedPiece, PlannedPieceSource, PlannedValue, VariableMaterializationPlan,
};
use inkwell::values::{IntValue, PointerValue};

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn composite_pieces_to_llvm_value(
        &mut self,
        materialization: &VariableMaterializationPlan,
        pieces: &[PlannedPiece],
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<IntValue<'ctx>> {
        let size = materialization
            .dwarf_type
            .as_ref()
            .map(|ty| ty.size())
            .unwrap_or(0);
        if size == 0 || size > 8 {
            return Err(CodeGenError::DwarfError(format!(
                "split variable '{}' does not fit one 8-byte scalar; print the whole value instead",
                materialization.name,
            )));
        }
        let status_ptr = if self.condition_context_active {
            Some(self.get_or_create_cond_error_global())
        } else if status_ptr.is_none()
            && pieces.iter().any(|piece| {
                matches!(
                    &piece.source,
                    PlannedPieceSource::Memory(_)
                        | PlannedPieceSource::Value(
                            PlannedValue::RuntimeComputed { .. }
                                | PlannedValue::AddressValue { .. }
                        )
                )
            })
        {
            // Expression callers may have no output status slot. Keep a local
            // status so a failed fragment invalidates the complete scalar.
            let function = self.current_function("allocate split scalar status")?;
            let entry = function.get_first_basic_block().ok_or_else(|| {
                CodeGenError::LLVMError("split scalar function has no entry block".into())
            })?;
            let builder = self.context.create_builder();
            if let Some(instruction) = entry.get_first_instruction() {
                builder.position_before(&instruction);
            } else {
                builder.position_at_end(entry);
            }
            let status = builder
                .build_alloca(self.context.i8_type(), "piece_scalar_status")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_store(status, self.context.i8_type().const_zero())
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            Some(status)
        } else {
            status_ptr
        };
        let module_hint = Self::module_path_for_offsets(materialization.module_path.as_deref())?;
        let mut value = self.context.i64_type().const_zero();
        for piece in pieces {
            let mut part = self.load_piece_value(
                piece,
                &materialization.name,
                status_ptr,
                module_hint.as_deref(),
            )?;
            if piece.byte_size < 8 {
                part = self
                    .builder
                    .build_and(
                        part,
                        self.context
                            .i64_type()
                            .const_int((1u64 << (piece.byte_size * 8)) - 1, false),
                        "piece_mask",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            }
            if piece.byte_offset != 0 {
                part = self
                    .builder
                    .build_left_shift(
                        part,
                        self.context
                            .i64_type()
                            .const_int((piece.byte_offset * 8) as u64, false),
                        "piece_shift",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            }
            value = self
                .builder
                .build_or(value, part, "piece_combine")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        if let Some(status_ptr) = status_ptr {
            let status = self
                .builder
                .build_load(self.context.i8_type(), status_ptr, "piece_scalar_status")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    status,
                    self.context.i8_type().const_zero(),
                    "piece_scalar_ok",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            return self
                .builder
                .build_select(
                    ok,
                    value,
                    self.context.i64_type().const_zero(),
                    "piece_scalar_or_zero",
                )
                .map(|value| value.into_int_value())
                .map_err(|error| CodeGenError::LLVMError(error.to_string()));
        }
        Ok(value)
    }

    pub(super) fn load_piece_value(
        &mut self,
        piece: &PlannedPiece,
        name: &str,
        status_ptr: Option<PointerValue<'ctx>>,
        module_hint: Option<&str>,
    ) -> Result<IntValue<'ctx>> {
        let status_ptr = if self.condition_context_active {
            Some(self.get_or_create_cond_error_global())
        } else {
            status_ptr
        };
        match &piece.source {
            PlannedPieceSource::Value(value) => self
                .planned_value_to_llvm_value(value, name, status_ptr, module_hint)
                .map(|value| value.into_int_value()),
            PlannedPieceSource::Memory(address) => {
                let address = self.resolve_planned_address(address, status_ptr, module_hint)?;
                let mut value = self.context.i64_type().const_zero();
                let mut offset = 0;
                // Read only the piece's bytes: rounding a three-byte piece up
                // to eight would spuriously fault at a page boundary.
                while offset < piece.byte_size {
                    let remaining = piece.byte_size - offset;
                    let size = match remaining {
                        8.. => MemoryAccessSize::U64,
                        4.. => MemoryAccessSize::U32,
                        2.. => MemoryAccessSize::U16,
                        _ => MemoryAccessSize::U8,
                    };
                    let addr = self
                        .builder
                        .build_int_add(
                            address.value,
                            self.context.i64_type().const_int(offset as u64, false),
                            "piece_read_address",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let addr = address.with_value(addr);
                    let mut part = if self.condition_context_active {
                        self.generate_memory_read_with_status(addr, size)
                    } else {
                        self.generate_memory_read(addr, size, status_ptr)
                    }?
                    .into_int_value();
                    if offset != 0 {
                        part = self
                            .builder
                            .build_left_shift(
                                part,
                                self.context
                                    .i64_type()
                                    .const_int((offset * 8) as u64, false),
                                "piece_read_shift",
                            )
                            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    }
                    value = self
                        .builder
                        .build_or(value, part, "piece_read_combine")
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    offset += size.bytes();
                }
                Ok(value)
            }
        }
    }
}

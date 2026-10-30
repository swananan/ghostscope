use super::*;
use ghostscope_dwarf::{PlannedPiece, PlannedPieceSource, PlannedValue};

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn emit_complex_format_pieces(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        payload_ptr: PointerValue<'ctx>,
        pieces: &[PlannedPiece],
        module_hint: Option<&str>,
        reserved_len: usize,
    ) -> Result<()> {
        let function = self.current_function("capture split variable")?;
        let finish = self.context.append_basic_block(function, "pieces_finish");
        let capture = crate::ebpf::helper_functions::MemoryReadErrorCapture {
            status_ptr,
            payload_ptr,
            reserved_len,
        };
        for (index, piece) in pieces.iter().enumerate() {
            // SAFETY: planning validated the complete piece layout against the
            // type size, which is included in this argument's reservation.
            let destination = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        payload_ptr,
                        &[self
                            .context
                            .i32_type()
                            .const_int(piece.byte_offset as u64, false)],
                        "piece_destination",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let computed_value = match &piece.source {
                PlannedPieceSource::Unavailable => {
                    // The capture type marks every intersecting field unavailable;
                    // these initialized bytes are never rendered as field values.
                    self.emit_complex_format_immediate_bytes(
                        destination,
                        &vec![0; piece.byte_size],
                    )?;
                    None
                }
                PlannedPieceSource::Memory(address) => {
                    let address = self.with_memory_read_error_capture(capture, |ctx| {
                        ctx.resolve_planned_address(address, Some(status_ptr), module_hint)
                    })?;
                    self.continue_if_piece_available(status_ptr, finish, "piece_address_ok")?;
                    self.emit_complex_format_memdump_at(
                        status_ptr,
                        payload_ptr,
                        destination,
                        &address,
                        piece.byte_size,
                        reserved_len,
                    )?;
                    None
                }
                PlannedPieceSource::Value(PlannedValue::ImplicitBytes(bytes)) => {
                    self.emit_complex_format_immediate_bytes(destination, bytes)?;
                    None
                }
                PlannedPieceSource::Value(_) => {
                    Some(self.with_memory_read_error_capture(capture, |ctx| {
                        ctx.load_piece_value(piece, "split variable", Some(status_ptr), module_hint)
                    })?)
                }
            };
            // A later successful piece must not overwrite a read-error payload
            // or turn an incomplete value into a successful capture.
            self.continue_if_piece_available(status_ptr, finish, &format!("piece_{index}_ok"))?;
            if let Some(value) = computed_value {
                self.emit_complex_format_computed_int(destination, value, piece.byte_size)?;
            }
        }
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(finish)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(finish);
        Ok(())
    }

    fn continue_if_piece_available(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        finish: inkwell::basic_block::BasicBlock<'ctx>,
        name: &str,
    ) -> Result<()> {
        let function = self.current_function("check split piece status")?;
        let status = self
            .builder
            .build_load(self.context.i8_type(), status_ptr, "piece_status")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                status,
                self.context.i8_type().const_zero(),
                "piece_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let next = self.context.append_basic_block(function, name);
        let failed = self.context.append_basic_block(function, "piece_failed");
        self.builder
            .build_conditional_branch(ok, next, failed)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(failed);
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(finish)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(next);
        Ok(())
    }
}

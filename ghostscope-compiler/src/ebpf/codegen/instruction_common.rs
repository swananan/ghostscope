use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn build_errno_i32(
        &self,
        ret: IntValue<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let i32_ty = self.context.i32_type();
        match ret.get_type().get_bit_width().cmp(&32) {
            std::cmp::Ordering::Greater => self
                .builder
                .build_int_truncate(ret, i32_ty, name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string())),
            std::cmp::Ordering::Less => self
                .builder
                .build_int_s_extend(ret, i32_ty, name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string())),
            std::cmp::Ordering::Equal => Ok(ret),
        }
    }
}

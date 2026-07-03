use crate::ebpf::context::{CodeGenError, EbpfContext, Result};
use crate::ebpf::expression_plan::SpecialVarPlan;
use inkwell::values::{BasicValueEnum, IntValue};
use inkwell::AddressSpace;
impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(crate) fn get_host_pid_tid_values(&mut self) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();

        // bpf_get_current_pid_tgid() returns:
        // - high 32 bits: TGID (process ID / getpid() view)
        // - low 32 bits: PID (thread ID / gettid() view)
        let host_pid_tgid = self.get_current_pid_tgid()?;
        let host_tid = self
            .builder
            .build_and(
                host_pid_tgid,
                i64_type.const_int(0xFFFF_FFFF, false),
                "host_tid",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let host_pid = self
            .builder
            .build_right_shift(
                host_pid_tgid,
                i64_type.const_int(32, false),
                false,
                "host_pid",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let host_pid_i32 = self
            .builder
            .build_int_truncate(host_pid, i32_type, "host_pid_i32")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let host_tid_i32 = self
            .builder
            .build_int_truncate(host_tid, i32_type, "host_tid_i32")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok((host_pid_i32, host_tid_i32))
    }

    pub(crate) fn get_special_pid_tid_values(
        &mut self,
    ) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
        const BPF_FUNC_GET_NS_CURRENT_PID_TGID: u64 = 120;
        const BPF_PIDNS_INFO_SIZE: u64 = 8; // struct { u32 pid; u32 tgid; }

        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let (host_pid_i32, host_tid_i32) = self.get_host_pid_tid_values()?;

        let ns_spec = if let Some(crate::PidFilterSpec::NamespaceTgid { pid_ns, .. }) =
            self.compile_options.pid_filter_spec
        {
            pid_ns.helper_dev_inode()
        } else {
            self.compile_options
                .special_pid_ns
                .and_then(|pid_ns| pid_ns.helper_dev_inode())
        };
        let Some((pid_ns_dev, pid_ns_inode)) = ns_spec else {
            let host_pid = self
                .builder
                .build_int_z_extend(host_pid_i32, i64_type, "selected_host_pid")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let host_tid = self
                .builder
                .build_int_z_extend(host_tid_i32, i64_type, "selected_host_tid")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            return Ok((host_pid, host_tid));
        };

        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let key_arr_ty = i32_type.array_type(4);
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        // Reuse entry-allocated stack key storage: helper only needs first 8 bytes.
        self.builder
            .build_store(key_alloca, key_arr_ty.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let pidns_info_ptr = self
            .builder
            .build_bit_cast(key_alloca, ptr_type, "special_pidns_info_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let helper_args = [
            i64_type.const_int(pid_ns_dev, false).into(),
            i64_type.const_int(pid_ns_inode, false).into(),
            pidns_info_ptr,
            i64_type.const_int(BPF_PIDNS_INFO_SIZE, false).into(),
        ];
        let helper_ret = self.create_bpf_helper_call(
            BPF_FUNC_GET_NS_CURRENT_PID_TGID,
            &helper_args,
            i64_type.into(),
            "special_ns_pid_tgid_ret",
        )?;
        let helper_ret = match helper_ret {
            BasicValueEnum::IntValue(v) => v,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "bpf_get_ns_current_pid_tgid did not return integer".to_string(),
                ))
            }
        };

        let helper_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                helper_ret,
                i64_type.const_zero(),
                "special_ns_helper_ok",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // SAFETY: key_alloca temporarily holds the two-field pid namespace helper
        // result, so [0, 0] addresses the pid field.
        let ns_pid_ptr = unsafe {
            self.builder.build_gep(
                key_arr_ty,
                key_alloca,
                &[i32_type.const_zero(), i32_type.const_zero()],
                "special_ns_pid_ptr",
            )
        }
        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // SAFETY: key_alloca temporarily holds the two-field pid namespace helper
        // result, so [0, 1] addresses the tgid field.
        let ns_tgid_ptr = unsafe {
            self.builder.build_gep(
                key_arr_ty,
                key_alloca,
                &[i32_type.const_zero(), i32_type.const_int(1, false)],
                "special_ns_tgid_ptr",
            )
        }
        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let ns_pid = self
            .builder
            .build_load(i32_type, ns_pid_ptr, "special_ns_pid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let ns_tgid = self
            .builder
            .build_load(i32_type, ns_tgid_ptr, "special_ns_tgid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();

        let selected_pid_i32 = self
            .builder
            .build_select(helper_ok, ns_tgid, host_pid_i32, "selected_pid_i32")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let selected_tid_i32 = self
            .builder
            .build_select(helper_ok, ns_pid, host_tid_i32, "selected_tid_i32")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        let selected_pid = self
            .builder
            .build_int_z_extend(selected_pid_i32, i64_type, "selected_pid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let selected_tid = self
            .builder
            .build_int_z_extend(selected_tid_i32, i64_type, "selected_tid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok((selected_pid, selected_tid))
    }

    /// Handle special variables like $pid, $tid, etc.
    pub fn handle_special_variable(&mut self, name: &str) -> Result<BasicValueEnum<'ctx>> {
        match self.plan_special_variable(name)? {
            SpecialVarPlan::Pid => {
                let (pid, _tid) = self.get_special_pid_tid_values()?;
                Ok(pid.into())
            }
            SpecialVarPlan::Tid => {
                let (_pid, tid) = self.get_special_pid_tid_values()?;
                Ok(tid.into())
            }
            SpecialVarPlan::HostPid => {
                let (host_pid, _host_tid) = self.get_host_pid_tid_values()?;
                let host_pid = self
                    .builder
                    .build_int_z_extend(host_pid, self.context.i64_type(), "selected_host_pid")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(host_pid.into())
            }
            SpecialVarPlan::InputPid => {
                let input_pid = self.compile_options.input_pid.ok_or_else(|| {
                    CodeGenError::NotImplemented(
                        "Special variable '$input_pid' is only available in -p mode".to_string(),
                    )
                })?;
                Ok(self
                    .context
                    .i64_type()
                    .const_int(input_pid as u64, false)
                    .into())
            }
            SpecialVarPlan::Timestamp => {
                // Use BPF helper to get current timestamp
                let ts = self.get_current_timestamp()?;
                Ok(ts.into())
            }
            SpecialVarPlan::Pc => self.load_special_register_value(16),
            SpecialVarPlan::Sp => self.load_special_register_value(7),
        }
    }

    fn load_special_register_value(&mut self, dwarf_reg: u16) -> Result<BasicValueEnum<'ctx>> {
        let pt_regs = self.get_pt_regs_parameter()?;
        self.load_register_value(dwarf_reg, pt_regs)
    }
}

//! CFI (Call Frame Information) index for fast CFA lookup
//!
//! This module provides efficient access to CFA (Canonical Frame Address) rules
//! by utilizing eh_frame_hdr's binary search table when available.

mod reader;
use reader::CfiReader;

use crate::{
    binary::{dwarf_endian_from_object, MappedFile},
    core::{CallerFrameRecovery, CfaResult, ModuleId, PlanExprOp, Result},
    semantics::{
        CfaRulePlan, CompactUnwindRow, CompactUnwindTable, RegisterRecoveryPlan, UnwindDiagnostic,
        UnwindDiagnosticKind,
    },
};
use anyhow::{anyhow, Context};
use ghostscope_platform::TargetArch;
use gimli::{
    BaseAddresses, CfaRule, CieOrFde, EhFrame, EhFrameHdr, FrameDescriptionEntry, ParsedEhFrameHdr,
    Register, RegisterRule, UnwindContext, UnwindSection,
};
use object::{Object, ObjectSection};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tracing::{debug, info, warn};

/// CFI index for fast CFA rule lookup
#[derive(Clone)]
pub struct CfiIndex {
    architecture: TargetArch,
    /// Keep file data alive
    _file_data: Arc<MappedFile>,
    /// Parsed eh_frame section
    eh_frame: EhFrame<CfiReader>,
    /// Parsed eh_frame_hdr for fast lookup (if available)
    eh_frame_hdr: Option<ParsedEhFrameHdr<CfiReader>>,
    /// Base addresses for DWARF sections
    bases: BaseAddresses,
    /// Encoding used when parsing CFI DWARF expressions.
    encoding: gimli::Encoding,
    /// Whether we have eh_frame_hdr for fast lookup
    has_fast_lookup: bool,
}

impl std::fmt::Debug for CfiIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CfiIndex")
            .field("has_fast_lookup", &self.has_fast_lookup)
            .field("has_eh_frame_hdr", &self.eh_frame_hdr.is_some())
            .finish()
    }
}

impl CfiIndex {
    /// Create a new CFI index from an object file data
    pub fn from_mapped_file(file_data: Arc<MappedFile>) -> Result<Self> {
        let object = file_data
            .parse_object()
            .context("Failed to parse object file")?;
        let architecture = match object.architecture() {
            object::Architecture::X86_64 => TargetArch::X86_64,
            object::Architecture::Aarch64 => TargetArch::Aarch64,
            _ => TargetArch::Unknown,
        };
        let endian = dwarf_endian_from_object(&object);
        let address_size = if object.is_64() { 8 } else { 4 };
        let encoding = gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size,
        };

        // Load eh_frame section (required)
        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .ok_or_else(|| anyhow!(".eh_frame section not found"))?;

        // Get section data range
        let (eh_frame_start, eh_frame_size) = eh_frame_section
            .file_range()
            .ok_or_else(|| anyhow!(".eh_frame section has no file range"))?;
        let eh_frame_reader = MappedFile::dwarf_reader_range(
            Arc::clone(&file_data),
            eh_frame_start,
            eh_frame_size,
            endian,
        )
        .ok_or_else(|| anyhow!("Invalid .eh_frame range in mapped file"))?;
        let mut eh_frame = EhFrame::from(CfiReader::new(
            eh_frame_reader,
            architecture == TargetArch::Aarch64,
        ));
        if architecture == TargetArch::Aarch64 {
            eh_frame.set_vendor(gimli::Vendor::AArch64);
        }

        // Try to load eh_frame_hdr for fast lookup (optional)
        let (eh_frame_hdr, has_fast_lookup) = match object.section_by_name(".eh_frame_hdr") {
            Some(hdr_section_obj) => {
                let (hdr_start, hdr_size) = hdr_section_obj
                    .file_range()
                    .ok_or_else(|| anyhow!(".eh_frame_hdr section has no file range"))?;
                let hdr_reader = MappedFile::dwarf_reader_range(
                    Arc::clone(&file_data),
                    hdr_start,
                    hdr_size,
                    endian,
                )
                .ok_or_else(|| anyhow!("Invalid .eh_frame_hdr range in mapped file"))?;
                let hdr_section = EhFrameHdr::from(CfiReader::new(
                    hdr_reader,
                    architecture == TargetArch::Aarch64,
                ));

                let mut bases = BaseAddresses::default();

                // Set eh_frame_hdr section base
                bases = bases.set_eh_frame_hdr(hdr_section_obj.address());

                match hdr_section.parse(&bases, address_size) {
                    Ok(parsed) => {
                        info!("Successfully parsed .eh_frame_hdr for fast FDE lookup");
                        (Some(parsed), true)
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse .eh_frame_hdr: {:?}, falling back to linear search",
                            e
                        );
                        (None, false)
                    }
                }
            }
            None => {
                debug!(".eh_frame_hdr not found, will use linear FDE search");
                (None, false)
            }
        };

        // Setup base addresses for all sections
        let mut bases = BaseAddresses::default();

        // Set eh_frame base
        if let Some(eh_frame_section) = object.section_by_name(".eh_frame") {
            bases = bases.set_eh_frame(eh_frame_section.address());
        }

        // Set text base (for function addresses)
        if let Some(text_section) = object.section_by_name(".text") {
            bases = bases.set_text(text_section.address());
        }

        // Set eh_frame_hdr base if we have it
        if let Some(hdr_section) = object.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(hdr_section.address());
        }

        Ok(Self {
            architecture,
            _file_data: file_data,
            eh_frame,
            eh_frame_hdr,
            bases,
            encoding,
            has_fast_lookup,
        })
    }

    /// Architecture of the object supplying CFI, independent of the host.
    pub fn architecture(&self) -> TargetArch {
        self.architecture
    }

    /// Get CFA rule for given PC (file offset) and convert to CfaResult
    pub fn get_cfa_result(&self, pc: u64) -> Result<CfaResult> {
        debug!("Looking up CFA rule for PC 0x{:x}", pc);
        let unwind_row = self.unwind_row_for_pc(pc)?;

        // 3. Convert gimli CfaRule to our CfaResult
        let cfa = match unwind_row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => CfaResult::RegisterPlusOffset {
                register: register.0,
                offset: *offset,
            },
            CfaRule::Expression(expr) => {
                let expression = expr.get(&self.eh_frame)?;
                let steps =
                    crate::dwarf_expr::cfa::parse_expression(expression.0.inner, self.encoding)?;
                CfaResult::Expression { steps }
            }
        };

        debug!("CFA result at PC 0x{:x}: {:?}", pc, cfa);

        Ok(cfa)
    }

    /// Recover a caller-frame register value as PlanExprOp[] that can be
    /// evaluated from the current frame state.
    pub fn recover_caller_register_steps(
        &self,
        pc: u64,
        register: u16,
    ) -> Result<Option<Vec<PlanExprOp>>> {
        let recovery = self.recover_caller_frame(pc, &[register])?;
        Ok(recovery.register_recovery_steps.get(&register).cloned())
    }

    /// Recover the direct caller frame at `pc` as PlanExprOp[].
    pub fn recover_caller_frame(&self, pc: u64, registers: &[u16]) -> Result<CallerFrameRecovery> {
        let fde = self.find_fde_for_address(pc)?;
        let mut ctx = UnwindContext::new();
        let unwind_row = fde
            .unwind_info_for_address(&self.eh_frame, &self.bases, &mut ctx, pc)
            .context("Failed to get unwind info for address")?
            .clone();

        let cfa_steps = self.cfa_steps(unwind_row.cfa())?;
        let return_address_register = fde.cie().return_address_register().0;
        let mut caller_pc_steps = self
            .register_rule_steps(&unwind_row, return_address_register)?
            .or_else(|| {
                (self.architecture == TargetArch::Aarch64
                    && return_address_register == 30
                    && unwind_row.register(Register(30)).is_none())
                    .then(|| vec![PlanExprOp::LoadRegister(30)])
            })
            .ok_or_else(|| {
                anyhow!(
                    "no caller PC recovery rule for DWARF register {return_address_register} at 0x{pc:x}"
                )
            })?;

        if self.return_address_signed(&unwind_row)? {
            let mask = ghostscope_platform::aarch64::native_instruction_address_mask().ok_or_else(
                || anyhow!("signed AArch64 return-address recovery requires a native PAC mask"),
            )?;
            caller_pc_steps.push(PlanExprOp::PushConstant(mask as i64));
            caller_pc_steps.push(PlanExprOp::And);
        }

        let mut register_recovery_steps = BTreeMap::new();
        for &register in registers {
            if register == return_address_register {
                register_recovery_steps.insert(register, caller_pc_steps.clone());
            } else if let Some(steps) = self.register_rule_steps(&unwind_row, register)? {
                register_recovery_steps.insert(register, steps);
            }
        }

        Ok(CallerFrameRecovery {
            cfa_steps,
            return_address_register,
            caller_pc_steps,
            register_recovery_steps,
        })
    }

    /// Compile all FDE rows into a compact unwind table for userspace/BPF planning.
    pub fn compact_unwind_table(&self, module: ModuleId) -> Result<CompactUnwindTable> {
        self.compact_unwind_table_with_max_rows(module, usize::MAX)
    }

    /// Compile at most `max_rows` FDE rows into a compact unwind table.
    pub fn compact_unwind_table_with_max_rows(
        &self,
        module: ModuleId,
        max_rows: usize,
    ) -> Result<CompactUnwindTable> {
        self.compact_unwind_table_with_max_rows_and_check(module, max_rows, &|| Ok(()))
    }

    /// Compile at most `max_rows` FDE rows while allowing a runtime caller to
    /// cooperatively stop long-running parsing.
    pub fn compact_unwind_table_with_max_rows_and_check(
        &self,
        module: ModuleId,
        max_rows: usize,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<CompactUnwindTable> {
        anyhow::ensure!(
            self.architecture.dwarf_register_roles().is_some(),
            "compact BPF unwind tables require a supported target ABI"
        );
        let started_at = Instant::now();
        let mut rows = Vec::new();
        let mut diagnostics = Vec::new();
        let mut entries = self.eh_frame.entries(&self.bases);
        let mut fde_count = 0usize;
        let mut truncated = false;

        while let Some(entry) = entries.next().context("Failed to iterate FDE entries")? {
            check()?;
            if rows.len() >= max_rows {
                truncated = true;
                break;
            }
            match entry {
                CieOrFde::Fde(partial_fde) => {
                    fde_count += 1;
                    let fde = partial_fde
                        .parse(|_, bases, offset| self.eh_frame.cie_from_offset(bases, offset))
                        .context("Failed to parse FDE")?;
                    self.append_compact_rows(
                        module,
                        &fde,
                        max_rows,
                        &mut rows,
                        &mut diagnostics,
                        check,
                    )?;
                }
                CieOrFde::Cie(_) => {}
            }
        }

        rows.sort_by_key(|row| (row.pc_start, row.pc_end));
        info!(
            ?module,
            fdes = fde_count,
            rows = rows.len(),
            diagnostics = diagnostics.len(),
            truncated,
            elapsed_ms = started_at.elapsed().as_millis(),
            "Built compact DWARF unwind table for bt"
        );
        Ok(CompactUnwindTable {
            module,
            rows,
            diagnostics,
        })
    }

    /// Find FDE for given address using eh_frame_hdr if available
    fn find_fde_for_address(
        &self,
        address: u64,
    ) -> Result<FrameDescriptionEntry<CfiReader, usize>> {
        if let Some(hdr) = &self.eh_frame_hdr {
            // Fast path: O(log n) binary search using eh_frame_hdr
            debug!(
                "Using eh_frame_hdr binary search for address 0x{:x}",
                address
            );

            let table = hdr
                .table()
                .ok_or_else(|| anyhow!("No search table in eh_frame_hdr"))?;

            table
                .fde_for_address(
                    &self.eh_frame,
                    &self.bases,
                    address,
                    |eh_frame, bases, offset| eh_frame.cie_from_offset(bases, offset),
                )
                .context("Failed to find FDE for address")
        } else {
            // Slow path: O(n) linear search through all FDEs
            debug!("Using linear FDE search for address 0x{:x}", address);

            let mut entries = self.eh_frame.entries(&self.bases);

            while let Some(entry) = entries.next().context("Failed to iterate FDE entries")? {
                match entry {
                    CieOrFde::Fde(partial_fde) => {
                        // Parse the FDE
                        let fde = partial_fde
                            .parse(|_, bases, offset| self.eh_frame.cie_from_offset(bases, offset))
                            .context("Failed to parse FDE")?;

                        // Check if address falls within this FDE's range
                        if fde.contains(address) {
                            return Ok(fde);
                        }
                    }
                    CieOrFde::Cie(_) => {
                        // Skip CIE entries
                    }
                }
            }

            Err(anyhow!("No FDE found for address 0x{address:x}"))
        }
    }

    fn unwind_row_for_pc(&self, pc: u64) -> Result<gimli::UnwindTableRow<usize>> {
        let fde = self.find_fde_for_address(pc)?;

        debug!(
            "Found FDE for PC 0x{:x}: initial_address=0x{:x}, range={}",
            pc,
            fde.initial_address(),
            fde.len()
        );

        let mut ctx = UnwindContext::new();
        fde.unwind_info_for_address(&self.eh_frame, &self.bases, &mut ctx, pc)
            .context("Failed to get unwind info for address")
            .cloned()
    }

    fn append_compact_rows(
        &self,
        module: ModuleId,
        fde: &FrameDescriptionEntry<CfiReader, usize>,
        max_rows: usize,
        rows: &mut Vec<CompactUnwindRow>,
        diagnostics: &mut Vec<UnwindDiagnostic>,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let return_address_register = fde.cie().return_address_register().0;
        let mut ctx = UnwindContext::new();
        let mut table = fde
            .rows(&self.eh_frame, &self.bases, &mut ctx)
            .context("Failed to build unwind rows")?;

        while let Some(row) = table.next_row().context("Failed to evaluate unwind row")? {
            check()?;
            if rows.len() >= max_rows {
                break;
            }
            let pc_start = row.start_address();
            let pc_end = row.end_address();
            if pc_start >= pc_end {
                continue;
            }

            let cfa = self.compact_cfa_rule(row.cfa(), pc_start, pc_end, diagnostics);
            let mut return_address = self.compact_register_rule(
                row.register(Register(return_address_register)).or_else(|| {
                    (self.architecture == TargetArch::Aarch64 && return_address_register == 30)
                        .then_some(RegisterRule::SameValue)
                }),
                return_address_register,
                pc_start,
                pc_end,
                true,
                diagnostics,
            );
            let return_address_signed = match self.return_address_signed(row) {
                Ok(signed) => signed,
                Err(error) => {
                    let reason = error.to_string();
                    self.push_unsupported_register_diagnostic(
                        return_address_register,
                        pc_start,
                        pc_end,
                        &reason,
                        diagnostics,
                    );
                    return_address = RegisterRecoveryPlan::Unsupported { reason };
                    false
                }
            };
            let sp = self.compact_optional_register_rule(
                row.register(Register(
                    self.architecture
                        .dwarf_register_roles()
                        .unwrap()
                        .stack_pointer,
                )),
                self.architecture
                    .dwarf_register_roles()
                    .unwrap()
                    .stack_pointer,
                pc_start,
                pc_end,
                diagnostics,
            );
            let rbp = self.compact_optional_register_rule(
                row.register(Register(
                    self.architecture
                        .dwarf_register_roles()
                        .unwrap()
                        .frame_pointer,
                ))
                .or_else(|| {
                    self.default_register_rule(
                        self.architecture
                            .dwarf_register_roles()
                            .unwrap()
                            .frame_pointer,
                    )
                }),
                self.architecture
                    .dwarf_register_roles()
                    .unwrap()
                    .frame_pointer,
                pc_start,
                pc_end,
                diagnostics,
            );
            rows.push(CompactUnwindRow {
                architecture: self.architecture,
                module,
                pc_start,
                pc_end,
                cfa,
                return_address_register,
                return_address_signed,
                return_address,
                sp,
                rbp,
            });
        }

        Ok(())
    }

    fn return_address_signed(&self, row: &gimli::UnwindTableRow<usize>) -> Result<bool> {
        if self.architecture != TargetArch::Aarch64 {
            return Ok(false);
        }
        match row.register(gimli::AArch64::RA_SIGN_STATE) {
            None | Some(RegisterRule::Constant(0)) => Ok(false),
            Some(RegisterRule::Constant(1)) => Ok(true),
            state => Err(anyhow!("unsupported AArch64 RA_SIGN_STATE: {state:?}")),
        }
    }

    fn compact_cfa_rule(
        &self,
        rule: &CfaRule<usize>,
        pc_start: u64,
        pc_end: u64,
        diagnostics: &mut Vec<UnwindDiagnostic>,
    ) -> CfaRulePlan {
        match rule {
            CfaRule::RegisterAndOffset { register, offset } => CfaRulePlan::RegPlusOffset {
                register: register.0,
                offset: *offset,
            },
            CfaRule::Expression(expr) => match self.parse_unwind_expression(*expr) {
                Ok(steps) => {
                    diagnostics.push(UnwindDiagnostic {
                        pc_start,
                        pc_end,
                        kind: UnwindDiagnosticKind::UnsupportedCfaRule {
                            reason: "CFA expression requires an expression template".to_string(),
                        },
                    });
                    CfaRulePlan::Expression { steps }
                }
                Err(error) => {
                    let reason = format!("failed to parse CFA expression: {error}");
                    diagnostics.push(UnwindDiagnostic {
                        pc_start,
                        pc_end,
                        kind: UnwindDiagnosticKind::UnsupportedCfaRule {
                            reason: reason.clone(),
                        },
                    });
                    CfaRulePlan::Unsupported { reason }
                }
            },
        }
    }

    fn compact_optional_register_rule(
        &self,
        rule: Option<RegisterRule<usize>>,
        register: u16,
        pc_start: u64,
        pc_end: u64,
        diagnostics: &mut Vec<UnwindDiagnostic>,
    ) -> Option<RegisterRecoveryPlan> {
        rule.map(|rule| {
            self.compact_register_rule(Some(rule), register, pc_start, pc_end, false, diagnostics)
        })
    }

    fn compact_register_rule(
        &self,
        rule: Option<RegisterRule<usize>>,
        register: u16,
        pc_start: u64,
        pc_end: u64,
        required: bool,
        diagnostics: &mut Vec<UnwindDiagnostic>,
    ) -> RegisterRecoveryPlan {
        match rule {
            Some(RegisterRule::Undefined) => RegisterRecoveryPlan::Undefined,
            None => {
                if required {
                    let reason =
                        format!("no return-address recovery rule for DWARF register {register}");
                    diagnostics.push(UnwindDiagnostic {
                        pc_start,
                        pc_end,
                        kind: UnwindDiagnosticKind::MissingReturnAddressRule { register },
                    });
                    RegisterRecoveryPlan::Unsupported { reason }
                } else {
                    RegisterRecoveryPlan::Undefined
                }
            }
            Some(RegisterRule::SameValue) => RegisterRecoveryPlan::SameValue { register },
            Some(RegisterRule::Register(other)) => {
                RegisterRecoveryPlan::Register { register: other.0 }
            }
            Some(RegisterRule::Offset(offset)) => RegisterRecoveryPlan::AtCfaOffset { offset },
            Some(RegisterRule::ValOffset(offset)) => RegisterRecoveryPlan::ValCfaOffset { offset },
            Some(RegisterRule::Constant(value)) => {
                self.push_unsupported_register_diagnostic(
                    register,
                    pc_start,
                    pc_end,
                    "constant register recovery is outside the BPF fast path",
                    diagnostics,
                );
                RegisterRecoveryPlan::Constant { value }
            }
            Some(RegisterRule::Expression(expr)) => {
                self.expression_register_plan(register, pc_start, pc_end, expr, true, diagnostics)
            }
            Some(RegisterRule::ValExpression(expr)) => {
                self.expression_register_plan(register, pc_start, pc_end, expr, false, diagnostics)
            }
            Some(RegisterRule::Architectural) => {
                let reason = "architectural register recovery is unsupported".to_string();
                self.push_unsupported_register_diagnostic(
                    register,
                    pc_start,
                    pc_end,
                    &reason,
                    diagnostics,
                );
                RegisterRecoveryPlan::Unsupported { reason }
            }
        }
    }

    fn expression_register_plan(
        &self,
        register: u16,
        pc_start: u64,
        pc_end: u64,
        expr: gimli::UnwindExpression<usize>,
        dereference: bool,
        diagnostics: &mut Vec<UnwindDiagnostic>,
    ) -> RegisterRecoveryPlan {
        match self.parse_unwind_expression(expr) {
            Ok(steps) => {
                self.push_unsupported_register_diagnostic(
                    register,
                    pc_start,
                    pc_end,
                    "register expression requires an expression template",
                    diagnostics,
                );
                RegisterRecoveryPlan::Expression { steps, dereference }
            }
            Err(error) => {
                let reason = format!("failed to parse register expression: {error}");
                self.push_unsupported_register_diagnostic(
                    register,
                    pc_start,
                    pc_end,
                    &reason,
                    diagnostics,
                );
                RegisterRecoveryPlan::Unsupported { reason }
            }
        }
    }

    fn push_unsupported_register_diagnostic(
        &self,
        register: u16,
        pc_start: u64,
        pc_end: u64,
        reason: &str,
        diagnostics: &mut Vec<UnwindDiagnostic>,
    ) {
        diagnostics.push(UnwindDiagnostic {
            pc_start,
            pc_end,
            kind: UnwindDiagnosticKind::UnsupportedRegisterRule {
                register,
                reason: reason.to_string(),
            },
        });
    }

    fn cfa_steps(&self, rule: &CfaRule<usize>) -> Result<Vec<PlanExprOp>> {
        match rule {
            CfaRule::RegisterAndOffset { register, offset } => {
                let mut steps = vec![PlanExprOp::LoadRegister(register.0)];
                if *offset != 0 {
                    steps.push(PlanExprOp::PushConstant(*offset));
                    steps.push(PlanExprOp::Add);
                }
                Ok(steps)
            }
            CfaRule::Expression(expr) => self.parse_unwind_expression(*expr),
        }
    }

    fn register_rule_steps(
        &self,
        unwind_row: &gimli::UnwindTableRow<usize>,
        register: u16,
    ) -> Result<Option<Vec<PlanExprOp>>> {
        let cfa_steps = self.cfa_steps(unwind_row.cfa())?;
        let rule = unwind_row
            .register(Register(register))
            .or_else(|| self.default_register_rule(register));

        match rule {
            Some(RegisterRule::Undefined) => Ok(None),
            Some(RegisterRule::SameValue) => Ok(Some(vec![PlanExprOp::LoadRegister(register)])),
            Some(RegisterRule::Register(other)) => {
                Ok(Some(vec![PlanExprOp::LoadRegister(other.0)]))
            }
            Some(RegisterRule::Offset(offset)) => {
                let mut steps = cfa_steps;
                if offset != 0 {
                    steps.push(PlanExprOp::PushConstant(offset));
                    steps.push(PlanExprOp::Add);
                }
                steps.push(PlanExprOp::Dereference {
                    size: crate::core::MemoryAccessSize::U64,
                });
                Ok(Some(steps))
            }
            Some(RegisterRule::ValOffset(offset)) => {
                let mut steps = cfa_steps;
                if offset != 0 {
                    steps.push(PlanExprOp::PushConstant(offset));
                    steps.push(PlanExprOp::Add);
                }
                Ok(Some(steps))
            }
            Some(RegisterRule::Expression(expr)) => {
                let mut steps = self.parse_unwind_expression(expr)?;
                steps.push(PlanExprOp::Dereference {
                    size: crate::core::MemoryAccessSize::U64,
                });
                Ok(Some(steps))
            }
            Some(RegisterRule::ValExpression(expr)) => {
                Ok(Some(self.parse_unwind_expression(expr)?))
            }
            Some(RegisterRule::Constant(value)) => {
                Ok(Some(vec![PlanExprOp::PushConstant(value as i64)]))
            }
            Some(RegisterRule::Architectural) | None => Ok(None),
        }
    }

    fn parse_unwind_expression(
        &self,
        expr: gimli::UnwindExpression<usize>,
    ) -> Result<Vec<PlanExprOp>> {
        let expression = expr.get(&self.eh_frame)?;
        crate::dwarf_expr::cfa::parse_expression(expression.0.inner, self.encoding)
    }

    fn default_register_rule(&self, register: u16) -> Option<RegisterRule<usize>> {
        self.architecture
            .is_callee_saved_gpr(register)
            .then_some(RegisterRule::SameValue)
    }

    /// Check if fast lookup is available
    pub fn has_fast_lookup(&self) -> bool {
        self.has_fast_lookup
    }

    /// Get statistics about the CFI index
    pub fn get_stats(&self) -> CfiStats {
        CfiStats {
            has_eh_frame_hdr: self.eh_frame_hdr.is_some(),
            has_fast_lookup: self.has_fast_lookup,
        }
    }
}

/// Statistics about CFI index
#[derive(Debug, Clone)]
pub struct CfiStats {
    pub has_eh_frame_hdr: bool,
    pub has_fast_lookup: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gimli::write::{
        Address, CallFrameInstruction, CommonInformationEntry, EndianVec,
        FrameDescriptionEntry as WriteFde, FrameTable,
    };

    fn fixture(architecture: object::Architecture, sp: u16, ra: u16, cfa_offset: i32) -> CfiIndex {
        fixture_with_instructions(architecture, sp, ra, cfa_offset, &[])
    }

    fn fixture_with_instructions(
        architecture: object::Architecture,
        sp: u16,
        ra: u16,
        cfa_offset: i32,
        instructions: &[(u32, CallFrameInstruction)],
    ) -> CfiIndex {
        let mut cie = CommonInformationEntry::new(
            gimli::Encoding {
                format: gimli::Format::Dwarf32,
                version: 1,
                address_size: 8,
            },
            1,
            -8,
            Register(ra),
        );
        cie.add_instruction(CallFrameInstruction::Cfa(Register(sp), cfa_offset));
        if architecture == object::Architecture::X86_64 {
            cie.add_instruction(CallFrameInstruction::Offset(Register(ra), -8));
        } else {
            // AArch64 leaves LR implicit until it is spilled.
            // AArch64 startup objects contain these even for unsigned fixture
            // functions; parsing must not discard the entire module table.
            cie.add_instruction(CallFrameInstruction::NegateRaState);
            cie.add_instruction(CallFrameInstruction::NegateRaState);
        }
        let mut frames = FrameTable::default();
        let cie_id = frames.add_cie(cie);
        let mut fde = WriteFde::new(Address::Constant(0x1000), 0x20);
        for (offset, instruction) in instructions {
            fde.add_instruction(*offset, instruction.clone());
        }
        frames.add_fde(cie_id, fde);
        let mut eh_frame = gimli::write::EhFrame::from(EndianVec::new(gimli::LittleEndian));
        frames.write_eh_frame(&mut eh_frame).unwrap();
        let mut object = object::write::Object::new(
            object::BinaryFormat::Elf,
            architecture,
            object::Endianness::Little,
        );
        let section = object.add_section(
            Vec::new(),
            b".eh_frame".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(section, eh_frame.slice(), 8);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), object.write().unwrap()).unwrap();
        CfiIndex::from_mapped_file(Arc::new(MappedFile::open(file.path()).unwrap())).unwrap()
    }

    #[test]
    fn target_elf_controls_cfi_recovery_independently_of_host() {
        let arm = fixture(object::Architecture::Aarch64, 31, 30, 0);
        assert_eq!(arm.architecture(), TargetArch::Aarch64);
        assert_eq!(
            arm.recover_caller_frame(0x1000, &[])
                .unwrap()
                .caller_pc_steps,
            vec![PlanExprOp::LoadRegister(30)]
        );
        assert_eq!(
            arm.recover_caller_register_steps(0x1000, 19).unwrap(),
            Some(vec![PlanExprOp::LoadRegister(19)])
        );
        assert_eq!(arm.recover_caller_register_steps(0x1000, 3).unwrap(), None);
        assert_eq!(arm.recover_caller_register_steps(0x1000, 18).unwrap(), None);
        let table = arm.compact_unwind_table(ModuleId(0)).unwrap();
        let plan = table.rows[0].bpf_fast_path_plan().unwrap();
        assert_eq!(plan.cfa_register, 31);
        assert_eq!(plan.return_address.register, 30);
        assert_eq!(plan.rbp.register, 29);

        let x86 = fixture(object::Architecture::X86_64, 7, 16, 8);
        assert_eq!(x86.architecture(), TargetArch::X86_64);
        assert_eq!(
            x86.recover_caller_register_steps(0x1000, 3).unwrap(),
            Some(vec![PlanExprOp::LoadRegister(3)])
        );
        assert_eq!(x86.recover_caller_register_steps(0x1000, 19).unwrap(), None);
        assert_eq!(x86.compact_unwind_table(ModuleId(0)).unwrap().rows.len(), 1);
    }

    #[test]
    fn arm64_signed_return_addresses_follow_cfi_state_transitions() {
        let cfi = fixture_with_instructions(
            object::Architecture::Aarch64,
            31,
            30,
            16,
            &[
                (4, CallFrameInstruction::NegateRaState),
                (8, CallFrameInstruction::Offset(Register(30), -8)),
                (12, CallFrameInstruction::NegateRaState),
            ],
        );
        let table = cfi.compact_unwind_table(ModuleId(0)).unwrap();
        assert_eq!(table.rows.len(), 4);
        for (index, signed) in [false, true, true, false].into_iter().enumerate() {
            let row = &table.rows[index];
            assert_eq!(row.pc_start, 0x1000 + 4 * index as u64);
            assert_eq!(row.return_address_signed, signed);
            assert_eq!(
                row.bpf_fast_path_plan().unwrap().return_address_signed,
                signed
            );
            let recovered = cfi.recover_caller_frame(row.pc_start, &[30]);
            if signed && !cfg!(target_arch = "aarch64") {
                assert!(recovered
                    .unwrap_err()
                    .to_string()
                    .contains("native PAC mask"));
                continue;
            }
            let recovered = recovered.unwrap();
            assert_eq!(
                recovered.register_recovery_steps[&30],
                recovered.caller_pc_steps
            );
            if signed {
                let mask = ghostscope_platform::aarch64::native_instruction_address_mask().unwrap();
                assert!(recovered
                    .caller_pc_steps
                    .ends_with(&[PlanExprOp::PushConstant(mask as i64), PlanExprOp::And,]));
            } else {
                assert!(!recovered.caller_pc_steps.contains(&PlanExprOp::And));
            }
        }
        assert!(matches!(
            table.rows[1].return_address,
            RegisterRecoveryPlan::SameValue { register: 30 }
        ));
        assert!(matches!(
            table.rows[2].return_address,
            RegisterRecoveryPlan::AtCfaOffset { offset: -8 }
        ));
    }

    #[test]
    fn arm64_unknown_sign_state_is_unsupported() {
        let cfi = fixture_with_instructions(
            object::Architecture::Aarch64,
            31,
            30,
            16,
            &[(
                0,
                CallFrameInstruction::SameValue(gimli::AArch64::RA_SIGN_STATE),
            )],
        );
        let table = cfi.compact_unwind_table(ModuleId(0)).unwrap();
        assert!(matches!(
            table.rows[0].return_address,
            RegisterRecoveryPlan::Unsupported { .. }
        ));
        assert!(table.rows[0].bpf_fast_path_plan().is_err());
        assert!(cfi
            .recover_caller_frame(0x1000, &[])
            .unwrap_err()
            .to_string()
            .contains("RA_SIGN_STATE"));
    }

    #[test]
    fn entry_sp_recovery_uses_target_call_frame_layout() {
        for (architecture, sp, ra, cfa_offset, correction) in [
            (object::Architecture::X86_64, 7, 16, 32, -8),
            (object::Architecture::Aarch64, 31, 30, 32, 0),
        ] {
            let cfi = fixture(architecture, sp, ra, cfa_offset);
            let steps = crate::dwarf_expr::entry_value::resolve_register_offset(
                0x1000,
                sp,
                16,
                8,
                None,
                None,
                Some(&cfi),
            )
            .unwrap();
            assert_eq!(
                steps,
                vec![
                    PlanExprOp::LoadRegister(sp),
                    PlanExprOp::PushConstant(32),
                    PlanExprOp::Add,
                    PlanExprOp::PushConstant(16 + correction),
                    PlanExprOp::Add,
                ]
            );
        }
    }
}

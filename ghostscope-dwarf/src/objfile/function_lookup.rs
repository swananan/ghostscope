use super::LoadedObjfile;
use crate::{
    binary::DwarfReader,
    core::{
        demangle::{demangle_by_lang_for_display, is_rust_mangled, RustSymbolHashDisplay},
        demangled_name, normalize_demangled_signature, symbol_name_matches_query, Result,
    },
    dwarf_expr::{errors as expr_errors, modes::DwarfExprMode},
    index::{GdbSymbolKind, LightweightIndex},
    parser::RangeExtractor,
    semantics::{
        range_contains_pc, resolve_attr_with_unit_origins, resolve_linkage_name_with_origins,
        resolve_origin_entry, InlineFrame,
    },
};
use gimli::Reader as _;
use object::{Object, ObjectSection};
use std::collections::HashSet;

// Optimized inline point entries observed from GCC/Clang sit only a few bytes
// before the first non-empty range. Keep the window small so distant
// caller-side setup PCs still fall back to the range start.
const MAX_INLINE_POINT_ENTRY_PC_GAP: u64 = 32;

#[derive(Clone, Copy)]
enum ParameterAbiClass {
    Integer,
    Sse,
    StackAggregate,
}

fn function_name_for_display(
    entry: &crate::core::IndexEntry,
    rust_hashes: RustSymbolHashDisplay,
) -> String {
    if !is_rust_mangled(&entry.name) {
        return entry.name.to_string();
    }

    demangle_by_lang_for_display(entry.language, &entry.name, rust_hashes)
        .unwrap_or_else(|| entry.name.to_string())
}

fn inline_function_name_for_display(
    linkage_name: Option<&str>,
    fallback_name: Option<&str>,
    rust_hashes: RustSymbolHashDisplay,
) -> Option<String> {
    linkage_name
        .filter(|name| is_rust_mangled(name))
        .and_then(|name| demangle_by_lang_for_display(Some(gimli::DW_LANG_Rust), name, rust_hashes))
        .or_else(|| fallback_name.map(str::to_owned))
}

impl LoadedObjfile {
    pub(crate) fn lookup_function_addresses(&self, name: &str) -> Vec<u64> {
        tracing::debug!("LoadedObjfile: looking up function '{}'", name);

        if let Err(error) = self.ensure_debug_info_for_symbol(name, GdbSymbolKind::Function, false)
        {
            tracing::warn!(
                "Failed to load indexed DWARF for function '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        let seed_entries = self
            .lightweight_index
            .read()
            .expect("lightweight index lock poisoned")
            .find_dies_by_function_name(name)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        if let Err(error) = self.ensure_debug_info_for_entries(&seed_entries) {
            tracing::warn!(
                "Failed to materialize indexed DWARF for function '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        let entries = self
            .lightweight_index
            .read()
            .expect("lightweight index lock poisoned")
            .find_dies_by_function_name(name)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut addresses = Vec::new();

        for entry in &entries {
            addresses.extend(self.compute_addresses_for_entry(entry));
        }

        if addresses.is_empty() {
            if let Some(symbol_starts) = self.text_symbol_starts_by_name.get(name) {
                tracing::debug!(
                    "LoadedObjfile: function '{}' has no concrete DWARF ranges; falling back to {} text symbol address(es)",
                    name,
                    symbol_starts.len()
                );
                addresses.extend(symbol_starts.iter().copied());
            }
        }

        tracing::debug!(
            "LoadedObjfile: function '{}' resolved to {} addresses: {:?}",
            name,
            addresses.len(),
            addresses
        );
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

    fn candidate_matches_name(
        name: &str,
        normalized_query: Option<&str>,
        entry: &crate::core::IndexEntry,
    ) -> bool {
        if symbol_name_matches_query(name, normalized_query, entry.name.as_ref(), None) {
            return true;
        }

        let should_attempt_demangle = entry.flags.is_linkage
            || crate::core::is_likely_mangled(entry.language, entry.name.as_ref());
        if !should_attempt_demangle {
            return false;
        }

        let demangled = demangled_name(entry.language, entry.name.as_ref());
        symbol_name_matches_query(
            name,
            normalized_query,
            entry.name.as_ref(),
            demangled.as_ref(),
        )
    }

    fn matching_fragment_candidate_indices(
        lightweight_index: &LightweightIndex,
        name: &str,
        candidate_indices: Vec<usize>,
        tag_filter: impl Fn(gimli::DwTag) -> bool,
    ) -> Vec<usize> {
        let normalized_query = normalize_demangled_signature(name);
        candidate_indices
            .into_iter()
            .filter(|&idx| {
                let Some(entry) = lightweight_index.entry(idx) else {
                    return false;
                };
                tag_filter(entry.tag)
                    && Self::candidate_matches_name(name, normalized_query.as_deref(), entry)
            })
            .collect()
    }

    fn scan_matching_candidate_indices(
        lightweight_index: &LightweightIndex,
        name: &str,
        tag_filter: impl Fn(gimli::DwTag) -> bool,
    ) -> Vec<usize> {
        let normalized_query = normalize_demangled_signature(name);
        let mut matches = Vec::new();

        for idx in (0..lightweight_index.entry_count()).rev() {
            let Some(entry) = lightweight_index.entry(idx) else {
                continue;
            };
            if tag_filter(entry.tag)
                && Self::candidate_matches_name(name, normalized_query.as_deref(), entry)
            {
                matches.push(idx);
            }
        }

        matches
    }

    fn function_candidate_indices(lightweight_index: &LightweightIndex, name: &str) -> Vec<usize> {
        let fragment_matches = Self::matching_fragment_candidate_indices(
            lightweight_index,
            name,
            lightweight_index.function_candidate_indices_by_fragment(name),
            |tag| {
                matches!(
                    tag,
                    gimli::constants::DW_TAG_subprogram
                        | gimli::constants::DW_TAG_inlined_subroutine
                )
            },
        );

        if !fragment_matches.is_empty() {
            return fragment_matches;
        }

        Self::scan_matching_candidate_indices(lightweight_index, name, |tag| {
            matches!(
                tag,
                gimli::constants::DW_TAG_subprogram | gimli::constants::DW_TAG_inlined_subroutine
            )
        })
    }

    fn variable_candidate_indices(lightweight_index: &LightweightIndex, name: &str) -> Vec<usize> {
        let fragment_matches = Self::matching_fragment_candidate_indices(
            lightweight_index,
            name,
            lightweight_index.variable_candidate_indices_by_fragment(name),
            |tag| tag == gimli::constants::DW_TAG_variable,
        );

        if !fragment_matches.is_empty() {
            return fragment_matches;
        }

        Self::scan_matching_candidate_indices(lightweight_index, name, |tag| {
            tag == gimli::constants::DW_TAG_variable
        })
    }

    fn matching_function_candidate_indices(&self, name: &str) -> Vec<usize> {
        if let Err(error) = self.ensure_debug_info_for_symbol(name, GdbSymbolKind::Function, true) {
            tracing::warn!(
                "Failed to load matching indexed DWARF for function '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        let seed_entries = {
            let lightweight_index = self
                .lightweight_index
                .read()
                .expect("lightweight index lock poisoned");
            Self::function_candidate_indices(&lightweight_index, name)
                .into_iter()
                .filter_map(|index| lightweight_index.entry(index).cloned())
                .collect::<Vec<_>>()
        };
        if let Err(error) = self.ensure_debug_info_for_entries(&seed_entries) {
            tracing::warn!(
                "Failed to materialize matching DWARF for function '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        let mut candidates = Self::function_candidate_indices(
            &self
                .lightweight_index
                .read()
                .expect("lightweight index lock poisoned"),
            name,
        );
        if candidates.is_empty() && self.uses_cu_name_index() {
            if let Err(error) = self.ensure_all_debug_info_for_name_index() {
                tracing::warn!(
                    "Failed to exhaust name-indexed DWARF for function '{}' in {}: {}",
                    name,
                    self.module_path().display(),
                    error
                );
            }
            candidates = Self::function_candidate_indices(
                &self
                    .lightweight_index
                    .read()
                    .expect("lightweight index lock poisoned"),
                name,
            );
        }
        candidates
    }

    pub(super) fn matching_variable_candidate_indices(&self, name: &str) -> Vec<usize> {
        if let Err(error) = self.ensure_debug_info_for_symbol(name, GdbSymbolKind::Variable, true) {
            tracing::warn!(
                "Failed to load matching indexed DWARF for variable '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        let seed_entries = {
            let lightweight_index = self
                .lightweight_index
                .read()
                .expect("lightweight index lock poisoned");
            Self::variable_candidate_indices(&lightweight_index, name)
                .into_iter()
                .filter_map(|index| lightweight_index.entry(index).cloned())
                .collect::<Vec<_>>()
        };
        if let Err(error) = self.ensure_debug_info_for_entries(&seed_entries) {
            tracing::warn!(
                "Failed to materialize matching DWARF for variable '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        let mut candidates = Self::variable_candidate_indices(
            &self
                .lightweight_index
                .read()
                .expect("lightweight index lock poisoned"),
            name,
        );
        if candidates.is_empty() && self.uses_cu_name_index() {
            if let Err(error) = self.ensure_all_debug_info_for_name_index() {
                tracing::warn!(
                    "Failed to exhaust name-indexed DWARF for variable '{}' in {}: {}",
                    name,
                    self.module_path().display(),
                    error
                );
            }
            candidates = Self::variable_candidate_indices(
                &self
                    .lightweight_index
                    .read()
                    .expect("lightweight index lock poisoned"),
                name,
            );
        }
        candidates
    }

    fn resolve_function_ranges(&self, entry: &crate::core::IndexEntry) -> Result<Vec<(u64, u64)>> {
        if !matches!(
            entry.tag,
            gimli::constants::DW_TAG_subprogram | gimli::constants::DW_TAG_inlined_subroutine
        ) {
            return Ok(Vec::new());
        }

        let cache_key = (entry.unit_offset.0 as u64, entry.die_offset.0 as u64);
        if let Some(ranges) = self
            .function_ranges_cache
            .read()
            .expect("function range cache lock poisoned")
            .get(&cache_key)
        {
            return Ok(ranges.clone());
        }

        let dwarf = self.dwarf();
        let unit = self.unit(entry.unit_offset)?;
        let die = unit
            .entry(entry.die_offset)
            .map_err(|e| anyhow::anyhow!("entry load error: {e}"))?;

        let ranges = RangeExtractor::extract_all_ranges(&die, &unit, dwarf)
            .map_err(|e| anyhow::anyhow!("range extraction error: {e}"))?;
        self.function_ranges_cache
            .write()
            .expect("function range cache lock poisoned")
            .insert(cache_key, ranges.clone());
        Ok(ranges)
    }

    pub(super) fn find_function_index_entry_by_address(
        &self,
        address: u64,
    ) -> Option<crate::core::IndexEntry> {
        if let Err(error) = self.ensure_debug_info_for_address(address) {
            tracing::warn!(
                "Failed to load indexed DWARF for address 0x{:x} in {}: {}",
                address,
                self.module_path().display(),
                error
            );
        }
        self.lightweight_index
            .read()
            .expect("lightweight index lock poisoned")
            .find_function_by_address(address, |entry| self.resolve_function_ranges(entry).ok())
            .cloned()
    }

    fn compute_addresses_for_entry(&self, entry: &crate::core::IndexEntry) -> Vec<u64> {
        let mut out = Vec::new();
        if let Err(error) = self.ensure_line_info_for_unit(entry.unit_offset) {
            tracing::warn!(
                "Failed to load line information for function '{}' in {}: {}",
                entry.name,
                self.module_path().display(),
                error
            );
        }
        let ranges = match self.resolve_function_ranges(entry) {
            Ok(ranges) => ranges,
            Err(err) => {
                tracing::warn!(
                    "Failed to resolve ranges for '{}' ({:?}/{:?}): {}",
                    entry.name,
                    entry.unit_offset,
                    entry.die_offset,
                    err
                );
                Vec::new()
            }
        };

        match entry.function_kind() {
            crate::core::FunctionDieKind::InlineInstance => {
                let mut debug_ranges = ranges.clone();
                debug_ranges.sort_unstable_by_key(|(s, _)| *s);
                if !debug_ranges.is_empty() {
                    let parts: Vec<String> = debug_ranges
                        .iter()
                        .map(|(s, e)| format!("(0x{s:x},0x{e:x})"))
                        .collect();
                    let epc_dbg = entry
                        .entry_pc
                        .map(|v| format!("0x{v:x}"))
                        .unwrap_or("None".to_string());
                    let rlen = debug_ranges.len();
                    let rlist = parts.join(", ");
                    tracing::debug!(
                        "Inline '{}' entry_pc={epc_dbg} ranges({rlen}): [{rlist}]",
                        entry.name
                    );
                } else {
                    let epc_dbg = entry
                        .entry_pc
                        .map(|v| format!("0x{v:x}"))
                        .unwrap_or("None".to_string());
                    tracing::debug!("Inline '{}' has no ranges; entry_pc={epc_dbg}", entry.name);
                }

                let entry_pc_has_line_entry = entry.entry_pc.is_some_and(|pc| {
                    self.line_mapping
                        .read()
                        .expect("line mapping lock poisoned")
                        .get_entries_in_range(pc, pc)
                        .next()
                        .is_some()
                });
                if let Some(addr) =
                    Self::selected_inline_address(entry, &ranges, entry_pc_has_line_entry)
                {
                    tracing::debug!("Inline '{}' selected=0x{addr:x}", entry.name);
                    out.push(addr);
                } else {
                    tracing::warn!(
                        "Inline entry has no usable address (no ranges/entry_pc): unit_off={:?}, die_off={:?}",
                        entry.unit_offset,
                        entry.die_offset
                    );
                }
            }
            crate::core::FunctionDieKind::ConcreteSubprogram => {
                let preferred_start = self.preferred_non_inline_symbol_start(entry, &ranges);
                let nranges = Self::selected_non_inline_ranges(entry, &ranges, preferred_start);
                // Line rows describe source statements, not control-flow dominance.
                // In optimized code even prologue_end can lie on only one path.
                // Only move past entry when parameters need prologue setup,
                // either for fixed callee-frame storage or a loclist whose
                // first available location starts after entry.
                for (start, end) in &nranges {
                    let needs_prologue = self
                        .function_parameters_need_prologue(entry, *start, *end)
                        .unwrap_or_else(|error| {
                            tracing::warn!(
                                "Failed to inspect parameter locations for '{}': {error}",
                                entry.name
                            );
                            false
                        });
                    let candidate = if needs_prologue {
                        let first_exec = self
                            .line_mapping
                            .read()
                            .expect("line mapping lock poisoned")
                            .find_first_executable_address(*start, *end);
                        Self::selected_non_inline_probe_address(*start, *end, first_exec)
                    } else {
                        *start
                    };
                    let candidate = if candidate != *start {
                        match self.validate_probe_advance(*start, candidate) {
                            Ok(()) => candidate,
                            Err(reason) => {
                                tracing::debug!(
                                    "Non-inline '{}' kept entry start=0x{start:x}, cannot advance to 0x{candidate:x}: {reason}",
                                    entry.name,
                                );
                                *start
                            }
                        }
                    } else {
                        candidate
                    };
                    let prefer_entry = candidate != *start
                        && self
                            .function_uses_entry_value_at(entry, candidate)
                            .unwrap_or(false);
                    let addr = if prefer_entry { *start } else { candidate };
                    if prefer_entry {
                        tracing::debug!(
                            "Non-inline '{}' entry_value active at 0x{candidate:x}, using entry start=0x{start:x}",
                            entry.name,
                        );
                    } else {
                        let off = addr.saturating_sub(*start);
                        tracing::debug!(
                            "Non-inline '{}' start=0x{start:x} first_exec=0x{addr:x} (+0x{off:x})",
                            entry.name
                        );
                        if addr == *start {
                            tracing::debug!(
                                "Non-inline '{}' kept entry start in range [0x{start:x}, 0x{end:x}), needs_prologue={needs_prologue}",
                                entry.name
                            );
                        }
                    }
                    out.push(addr);
                }
            }
            crate::core::FunctionDieKind::AbstractSubprogram => {
                tracing::debug!(
                    "Skipping abstract subprogram '{}' with no concrete code ranges",
                    entry.name
                );
            }
            crate::core::FunctionDieKind::NotFunction => {}
        }
        out
    }

    fn preferred_non_inline_symbol_start(
        &self,
        entry: &crate::core::IndexEntry,
        ranges: &[(u64, u64)],
    ) -> Option<u64> {
        if entry.entry_pc.is_some() || ranges.len() <= 1 {
            return None;
        }

        self.text_symbol_starts_by_name
            .get(entry.name.as_ref())?
            .iter()
            .copied()
            .filter(|address| {
                ranges
                    .iter()
                    .any(|(start, end)| *start <= *address && *address < *end)
            })
            .min()
    }

    fn selected_inline_address(
        entry: &crate::core::IndexEntry,
        ranges: &[(u64, u64)],
        entry_pc_has_line_entry: bool,
    ) -> Option<u64> {
        let first_start = ranges.first().map(|(start, _)| *start);
        let low_pc = ranges.iter().map(|(start, _)| *start).min();
        // Optimized inline DIEs can have a point entry_pc just before the
        // non-empty DW_AT_ranges. Keep it when the line table confirms the PC.
        let line_table_point_entry_pc = entry.entry_pc.filter(|pc| {
            entry_pc_has_line_entry
                && first_start.is_some_and(|start| {
                    *pc < start && start.saturating_sub(*pc) <= MAX_INLINE_POINT_ENTRY_PC_GAP
                })
        });

        entry
            .validated_entry_pc(ranges)
            .or(line_table_point_entry_pc)
            .or(first_start)
            .or(low_pc)
            .or(entry.representative_addr)
    }

    fn selected_non_inline_ranges(
        entry: &crate::core::IndexEntry,
        ranges: &[(u64, u64)],
        preferred_start: Option<u64>,
    ) -> Vec<(u64, u64)> {
        let ranges = ranges.to_vec();
        if ranges.len() <= 1 {
            return ranges;
        }

        if let Some(entry_pc) = entry.entry_pc {
            if let Some(range) = ranges
                .iter()
                .copied()
                .find(|(start, end)| *start <= entry_pc && entry_pc < *end)
            {
                return vec![range];
            }
        }

        if let Some(preferred_start) = preferred_start {
            if let Some(range) = ranges
                .iter()
                .copied()
                .find(|(start, end)| *start <= preferred_start && preferred_start < *end)
            {
                return vec![range];
            }
        }

        vec![ranges[0]]
    }

    fn selected_non_inline_probe_address(start: u64, end: u64, candidate: u64) -> u64 {
        if start <= candidate && candidate < end {
            candidate
        } else {
            start
        }
    }

    fn validate_probe_advance(&self, start: u64, candidate: u64) -> Result<()> {
        let object = self._binary_mapped_file.parse_object()?;
        anyhow::ensure!(
            object.architecture() == object::Architecture::X86_64,
            "unsupported architecture for probe instruction decoding"
        );
        let size = candidate
            .checked_sub(start)
            .ok_or_else(|| anyhow::anyhow!("candidate precedes entry"))?;
        for section in object.sections() {
            if section.kind() == object::SectionKind::Text {
                if let Some(code) = section.data_range(start, size)? {
                    return Self::validate_linear_instructions(code, start);
                }
            }
        }
        anyhow::bail!("cannot read instructions between entry and candidate")
    }

    // Decode complete instructions rather than searching for opcode bytes:
    // immediates and displacements can contain the same bytes as branches.
    // Any decoding failure also keeps the probe at entry.
    fn validate_linear_instructions(code: &[u8], start: u64) -> Result<()> {
        let mut decoder =
            iced_x86::Decoder::with_ip(64, code, start, iced_x86::DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            let pc = instruction.ip();
            anyhow::ensure!(
                !instruction.is_invalid(),
                "invalid or truncated instruction at 0x{pc:x}"
            );
            let flow = instruction.flow_control();
            anyhow::ensure!(
                flow == iced_x86::FlowControl::Next,
                "control-flow instruction {flow:?} at 0x{pc:x}"
            );
        }
        Ok(())
    }

    fn function_parameters_need_prologue(
        &self,
        idx_entry: &crate::core::IndexEntry,
        start: u64,
        end: u64,
    ) -> Result<bool> {
        let dwarf = self.dwarf();
        let unit = self.unit(idx_entry.unit_offset)?;
        let entry = unit.entry(idx_entry.die_offset)?;
        let frame_base_is_cfa =
            match resolve_attr_with_unit_origins(dwarf, &entry, &unit, gimli::DW_AT_frame_base)? {
                Some(gimli::AttributeValue::Exprloc(expression)) => matches!(
                    crate::dwarf_expr::ops::parse_single_op(
                        expression.0,
                        unit.encoding(),
                        "parameter frame base",
                    )?,
                    Some(gimli::Operation::CallFrameCFA)
                ),
                _ => false,
            };
        let normal_calling_convention = matches!(
            resolve_attr_with_unit_origins(dwarf, &entry, &unit, gimli::DW_AT_calling_convention)?,
            None | Some(gimli::AttributeValue::CallingConvention(
                gimli::DW_CC_normal
            ))
        );
        let mut integer_parameters = 0usize;
        let mut sse_parameters = 0usize;
        let mut parameter_index = 0;
        let mut sysv_stack_offset = 0;
        let mut scalar_layout = true;
        let mut tree = unit.entries_tree(Some(idx_entry.die_offset))?;
        let root = tree.root()?;
        let mut children = root.children();
        while let Some(child) = children.next()? {
            let parameter = child.entry();
            if parameter.tag() != gimli::DW_TAG_formal_parameter {
                continue;
            }
            // A positive CFA offset alone does not establish entry availability:
            // GCC can omit the ms_abi marker; its register home slots also
            // live above the CFA. Only exempt scalar arguments after exhausting
            // their SysV register class (six integer or eight SSE arguments).
            // Such arguments are also beyond the four register slots of ms_abi.
            // Require the actual slot to agree with one of these caller layouts.
            let abi_class = Self::parameter_abi_class(dwarf, &unit, parameter);
            let on_stack = match abi_class {
                Some(ParameterAbiClass::Integer) => {
                    let on_stack = integer_parameters >= 6;
                    integer_parameters += 1;
                    on_stack
                }
                Some(ParameterAbiClass::Sse) => {
                    let on_stack = sse_parameters >= 8;
                    sse_parameters += 1;
                    on_stack
                }
                Some(ParameterAbiClass::StackAggregate) | None => {
                    scalar_layout = false;
                    false
                }
            };
            let incoming_stack_offsets = (on_stack && scalar_layout && normal_calling_convention)
                .then_some((sysv_stack_offset, parameter_index * 8));
            if on_stack {
                sysv_stack_offset += 8;
            }
            parameter_index += 1;
            let Some(value) =
                resolve_attr_with_unit_origins(dwarf, parameter, &unit, gimli::DW_AT_location)?
            else {
                continue;
            };
            if let gimli::AttributeValue::Exprloc(expression) = value {
                let operations = crate::dwarf_expr::ops::parse_ops(
                    expression.0,
                    unit.encoding(),
                    "parameter frame location",
                )?;
                let cfa_offset = match operations.as_slice() {
                    [gimli::Operation::FrameOffset { offset }] if frame_base_is_cfa => {
                        Some(*offset)
                    }
                    [gimli::Operation::RegisterOffset {
                        register, offset, ..
                    }] if incoming_stack_offsets.is_some() => {
                        // The expression may use a post-prologue RSP/RBP value.
                        // Do not interpret it as an incoming slot if frame setup
                        // changes the register's relation to the CFA.
                        let statement = self
                            .line_mapping
                            .read()
                            .expect("line mapping lock poisoned")
                            .find_first_executable_address(start, end);
                        let entry_cfa = self.unwind_info.get_cfa_result(start).ok().flatten();
                        let statement_cfa =
                            self.unwind_info.get_cfa_result(statement).ok().flatten();
                        match entry_cfa {
                            Some(crate::core::CfaResult::RegisterPlusOffset {
                                register: cfa_register,
                                offset: cfa_offset,
                            }) if register.0 == cfa_register && entry_cfa == statement_cfa => {
                                offset.checked_sub(cfa_offset)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                let known_incoming_location = matches!((cfa_offset, incoming_stack_offsets),
                    (Some(offset), Some((sysv, ms))) if offset == sysv || offset == ms)
                    // SysV passes aggregates larger than 16 bytes on the stack.
                    // ms_abi passes them indirectly, so a bare fbreg cannot be
                    // an uninitialized register home slot for such a value.
                    // The frame base must also be valid at entry: Clang's
                    // fixed RBP frame base still needs its prologue setup.
                    || (normal_calling_convention
                        && frame_base_is_cfa
                        && matches!(abi_class, Some(ParameterAbiClass::StackAggregate))
                        && matches!(operations.as_slice(),
                            [gimli::Operation::FrameOffset { offset }] if *offset >= 0));
                if !known_incoming_location
                    && operations.iter().any(|op| {
                        matches!(
                            op,
                            gimli::Operation::FrameOffset { .. }
                                | gimli::Operation::CallFrameCFA
                                | gimli::Operation::RegisterOffset {
                                    register: gimli::Register(6 | 7),
                                    ..
                                }
                        )
                    })
                {
                    return Ok(true);
                }
            } else if Self::parameter_location_starts_after_entry(dwarf, &unit, value, start, end)?
            {
                // Rust -O0 indirect aggregate parameters can have loclists
                // beginning only after their argument pointers are spilled.
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Identify scalar register classes and large by-value stack aggregates.
    /// Unknown types do not establish that a parameter is caller-initialized.
    fn parameter_abi_class(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        parameter: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Option<ParameterAbiClass> {
        use crate::semantics::{origins::ResolvedUnit, resolve_type_ref_with_origins};
        let mut loc = resolve_type_ref_with_origins(dwarf, parameter, unit).ok()??;
        let mut type_unit = ResolvedUnit::Borrowed(unit);
        let mut visited = HashSet::new();
        while visited.len() < 64 && visited.insert((loc.object, loc.cu_off, loc.die_off)) {
            if loc.object != crate::binary::references::unit_object(dwarf, &type_unit)
                || type_unit.header.debug_info_offset() != Some(loc.cu_off)
            {
                type_unit = ResolvedUnit::Owned(Box::new(loc.unit(dwarf).ok()?));
            }
            let entry = type_unit.entry(loc.die_off).ok()?;
            let size = entry
                .attr_value(gimli::DW_AT_byte_size)
                .and_then(crate::core::attr_u64);
            match entry.tag() {
                gimli::DW_TAG_typedef
                | gimli::DW_TAG_const_type
                | gimli::DW_TAG_volatile_type
                | gimli::DW_TAG_restrict_type
                | gimli::DW_TAG_atomic_type => {
                    loc = resolve_type_ref_with_origins(dwarf, &entry, &type_unit).ok()??;
                }
                gimli::DW_TAG_pointer_type
                | gimli::DW_TAG_reference_type
                | gimli::DW_TAG_rvalue_reference_type
                    if matches!(
                        size.unwrap_or(u64::from(type_unit.header.address_size())),
                        1..=8
                    ) =>
                {
                    return Some(ParameterAbiClass::Integer);
                }
                gimli::DW_TAG_enumeration_type if matches!(size, Some(1..=8)) => {
                    return Some(ParameterAbiClass::Integer);
                }
                gimli::DW_TAG_structure_type
                | gimli::DW_TAG_class_type
                | gimli::DW_TAG_union_type
                    if size.is_some_and(|size| size > 16) =>
                {
                    return Some(ParameterAbiClass::StackAggregate);
                }
                gimli::DW_TAG_base_type if matches!(size, Some(1..=8)) => {
                    return match entry.attr_value(gimli::DW_AT_encoding) {
                        Some(gimli::AttributeValue::Encoding(
                            gimli::DW_ATE_signed
                            | gimli::DW_ATE_unsigned
                            | gimli::DW_ATE_signed_char
                            | gimli::DW_ATE_unsigned_char
                            | gimli::DW_ATE_boolean
                            | gimli::DW_ATE_address
                            | gimli::DW_ATE_UTF,
                        )) => Some(ParameterAbiClass::Integer),
                        Some(gimli::AttributeValue::Encoding(gimli::DW_ATE_float))
                            if matches!(size, Some(4 | 8)) =>
                        {
                            Some(ParameterAbiClass::Sse)
                        }
                        _ => None,
                    };
                }
                _ => return None,
            }
        }
        None
    }

    fn parameter_location_starts_after_entry(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        value: gimli::AttributeValue<DwarfReader>,
        start: u64,
        end: u64,
    ) -> Result<bool> {
        let value = match value {
            gimli::AttributeValue::SecOffset(offset) => {
                gimli::AttributeValue::LocationListsRef(gimli::LocationListsOffset(offset))
            }
            value => value,
        };
        let Some(mut locations) = dwarf.attr_locations(unit, value)? else {
            return Ok(false);
        };
        let mut entry_available = None;
        let mut default_available = false;
        let mut later_available = false;
        while let Some(location) = locations.next()? {
            let available = !location.data.0.is_empty();
            // gimli represents DW_LLE_default_location with the full range.
            // An explicit entry range, including an empty expression, wins.
            if location.range.begin == 0 && location.range.end == u64::MAX {
                default_available = available;
            } else if range_contains_pc(location.range.begin, location.range.end, start) {
                if available {
                    return Ok(false);
                }
                entry_available = Some(available);
            } else if start < location.range.begin && location.range.begin < end && available {
                later_available = true;
            }
        }
        Ok(!entry_available.unwrap_or(default_available) && later_available)
    }

    fn function_uses_entry_value_at(
        &self,
        idx_entry: &crate::core::IndexEntry,
        pc: u64,
    ) -> Result<bool> {
        let dwarf = self.dwarf();
        let unit = self.unit(idx_entry.unit_offset)?;
        let entry = unit
            .entry(idx_entry.die_offset)
            .map_err(|e| anyhow::anyhow!("entry load error: {e}"))?;
        Self::subprogram_uses_entry_value_at(dwarf, &unit, &entry, pc)
    }

    #[cfg(test)]
    fn subprogram_uses_entry_value(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<bool> {
        let mut visited = HashSet::with_capacity(4);
        if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
            visited.insert(entry_abs);
        }

        Self::subprogram_uses_entry_value_with_pc(dwarf, unit, entry, None, &mut visited)
    }

    fn subprogram_uses_entry_value_at(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: u64,
    ) -> Result<bool> {
        let mut visited = HashSet::with_capacity(4);
        if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
            visited.insert(entry_abs);
        }

        Self::subprogram_uses_entry_value_with_pc(dwarf, unit, entry, Some(pc), &mut visited)
    }

    fn subprogram_uses_entry_value_with_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: Option<u64>,
        visited: &mut HashSet<gimli::DebugInfoOffset>,
    ) -> Result<bool> {
        if entry.tag() != gimli::constants::DW_TAG_subprogram {
            return Ok(false);
        }

        if let Some(uses_entry_value) =
            Self::direct_formal_parameters_entry_value_state_with_pc(dwarf, unit, entry, pc)?
        {
            return Ok(uses_entry_value);
        }

        for origin_attr in [
            gimli::constants::DW_AT_abstract_origin,
            gimli::constants::DW_AT_specification,
        ] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some((origin_abs, origin_unit, origin_entry)) =
                    resolve_origin_entry(dwarf, unit, value)
                        .map_err(|e| anyhow::anyhow!("origin resolution error: {e}"))?
                {
                    if visited.insert(origin_abs)
                        && Self::subprogram_uses_entry_value_with_pc(
                            dwarf,
                            &origin_unit,
                            &origin_entry,
                            pc,
                            visited,
                        )?
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    #[cfg(test)]
    fn direct_formal_parameters_entry_value_state(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<Option<bool>> {
        Self::direct_formal_parameters_entry_value_state_with_pc(dwarf, unit, entry, None)
    }

    fn direct_formal_parameters_entry_value_state_with_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: Option<u64>,
    ) -> Result<Option<bool>> {
        let mut saw_parameter = false;

        if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
            if let Ok(root) = tree.root() {
                let mut children = root.children();
                while let Ok(Some(child)) = children.next() {
                    let e = child.entry();
                    if e.tag() != gimli::constants::DW_TAG_formal_parameter {
                        continue;
                    }
                    saw_parameter = true;

                    if let Ok(Some(value)) = resolve_attr_with_unit_origins(
                        dwarf,
                        e,
                        unit,
                        gimli::constants::DW_AT_location,
                    ) {
                        if Self::attribute_uses_entry_value(dwarf, unit, value, pc)? {
                            return Ok(Some(true));
                        }
                    }
                }
            }
        }

        if saw_parameter {
            Ok(Some(false))
        } else {
            Ok(None)
        }
    }

    fn attribute_uses_entry_value(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        value: gimli::AttributeValue<DwarfReader>,
        pc: Option<u64>,
    ) -> Result<bool> {
        match value {
            gimli::AttributeValue::Exprloc(expr) => Ok(Self::expression_uses_entry_value(
                unit,
                gimli::Expression(expr.0),
            )),
            gimli::AttributeValue::LocationListsRef(offset) => match pc {
                Some(pc) => Self::location_list_uses_entry_value_at_pc(
                    dwarf,
                    unit,
                    gimli::LocationListsOffset(offset.0),
                    pc,
                ),
                None => Ok(false),
            },
            gimli::AttributeValue::DebugLocListsIndex(index) => match pc {
                Some(pc) => {
                    let offset = dwarf.locations_offset(unit, index)?;
                    Self::location_list_uses_entry_value_at_pc(dwarf, unit, offset, pc)
                }
                None => Ok(false),
            },
            gimli::AttributeValue::SecOffset(offset) => match pc {
                Some(pc) => Self::location_list_uses_entry_value_at_pc(
                    dwarf,
                    unit,
                    gimli::LocationListsOffset(offset),
                    pc,
                ),
                None => Ok(false),
            },
            _ => Ok(false),
        }
    }

    fn location_list_uses_entry_value_at_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        offset: gimli::LocationListsOffset<usize>,
        pc: u64,
    ) -> Result<bool> {
        let mut raw_locations = match dwarf.raw_locations(unit, offset) {
            Ok(iter) => iter,
            Err(_) => return Ok(false),
        };

        let mut base_address = unit.low_pc;
        let mut default_location_uses_entry_value = None;
        while let Some(raw_entry) = raw_locations
            .next()
            .map_err(|e| anyhow::anyhow!("raw location list iteration error: {e:?}"))?
        {
            match raw_entry {
                gimli::RawLocListEntry::BaseAddress { addr } => {
                    base_address = addr;
                }
                gimli::RawLocListEntry::BaseAddressx { addr } => {
                    if let Ok(resolved) = dwarf.address(unit, addr) {
                        base_address = resolved;
                    }
                }
                gimli::RawLocListEntry::StartLength {
                    begin,
                    length,
                    data,
                } => {
                    if range_contains_pc(begin, begin.wrapping_add(length), pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::StartEnd { begin, end, data } => {
                    if range_contains_pc(begin, end, pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::OffsetPair { begin, end, data }
                | gimli::RawLocListEntry::AddressOrOffsetPair { begin, end, data } => {
                    let start = base_address.wrapping_add(begin);
                    let end_addr = base_address.wrapping_add(end);
                    if range_contains_pc(start, end_addr, pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::StartxLength {
                    begin,
                    length,
                    data,
                } => {
                    if let Ok(start) = dwarf.address(unit, begin) {
                        if range_contains_pc(start, start.wrapping_add(length), pc) {
                            return Ok(Self::expression_uses_entry_value(unit, data));
                        }
                    }
                }
                gimli::RawLocListEntry::StartxEndx { begin, end, data } => {
                    if let (Ok(start), Ok(end_addr)) =
                        (dwarf.address(unit, begin), dwarf.address(unit, end))
                    {
                        if range_contains_pc(start, end_addr, pc) {
                            return Ok(Self::expression_uses_entry_value(unit, data));
                        }
                    }
                }
                gimli::RawLocListEntry::DefaultLocation { data } => {
                    default_location_uses_entry_value =
                        Some(Self::expression_uses_entry_value(unit, data));
                }
            }
        }

        Ok(default_location_uses_entry_value.unwrap_or(false))
    }

    fn expression_uses_entry_value(
        unit: &gimli::Unit<DwarfReader>,
        expression: gimli::Expression<DwarfReader>,
    ) -> bool {
        expr_errors::silent_false(
            DwarfExprMode::ScanOnly,
            crate::dwarf_expr::scan::contains_entry_value(expression, unit.encoding()),
        )
    }

    pub(crate) fn lookup_function_addresses_any(&self, name: &str) -> Vec<u64> {
        let addrs = self.lookup_function_addresses(name);
        if !addrs.is_empty() {
            return addrs;
        }

        let mut out = Vec::new();
        let candidate_indices = self.matching_function_candidate_indices(name);
        let entries = {
            let lightweight_index = self
                .lightweight_index
                .read()
                .expect("lightweight index lock poisoned");
            candidate_indices
                .into_iter()
                .filter_map(|idx| lightweight_index.entry(idx).cloned())
                .collect::<Vec<_>>()
        };
        for entry in &entries {
            out.extend(self.compute_addresses_for_entry(entry));
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    pub(crate) fn find_function_name_by_address(&self, address: u64) -> Option<String> {
        self.find_function_name_by_address_for_display(address, RustSymbolHashDisplay::Shown)
    }

    pub(crate) fn find_function_name_by_address_for_display(
        &self,
        address: u64,
        rust_hashes: RustSymbolHashDisplay,
    ) -> Option<String> {
        self.find_function_index_entry_by_address(address)
            .map(|entry| function_name_for_display(&entry, rust_hashes))
    }

    pub(crate) fn find_inline_function_name_for_display(
        &self,
        inline_frame: &InlineFrame,
        rust_hashes: RustSymbolHashDisplay,
    ) -> Option<String> {
        let cu_offset = gimli::DebugInfoOffset(inline_frame.concrete_die.cu.0 as usize);
        let die_offset = gimli::UnitOffset(inline_frame.concrete_die.offset as usize);
        let linkage_name = self
            .unit_in(inline_frame.concrete_die.cu.1, cu_offset)
            .ok()
            .and_then(|unit| {
                let entry = unit.entry(die_offset).ok()?;
                resolve_linkage_name_with_origins(self.dwarf(), &unit, &entry)
                    .ok()
                    .flatten()
            });

        inline_function_name_for_display(
            linkage_name.as_deref(),
            inline_frame.function_name.as_deref(),
            rust_hashes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::LoadedObjfile;
    use super::{function_name_for_display, inline_function_name_for_display};
    use crate::binary::{dwarf_reader_from_arc, DwarfReader};
    use crate::core::{demangle::RustSymbolHashDisplay, FunctionDieKind, IndexEntry, IndexFlags};
    use crate::index::LightweightIndex;
    use gimli::constants;
    use gimli::write::{
        Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
        Expression as WriteExpression, LineProgram, Location, LocationList, Sections, Unit,
    };
    use gimli::{Format, Register};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn subprogram_entry(ranges: &[(u64, u64)], entry_pc: Option<u64>) -> IndexEntry {
        IndexEntry {
            name: Arc::from("CGPsend"),
            die_offset: gimli::UnitOffset(0),
            unit_offset: gimli::DebugInfoOffset(0),
            lexical_scope: None,
            tag: constants::DW_TAG_subprogram,
            flags: IndexFlags::default(),
            language: None,
            representative_addr: ranges.first().map(|(start, _)| *start).or(entry_pc),
            entry_pc,
            function_kind: FunctionDieKind::ConcreteSubprogram,
        }
    }

    fn inline_entry(ranges: &[(u64, u64)], entry_pc: Option<u64>) -> IndexEntry {
        let mut entry = subprogram_entry(ranges, entry_pc);
        entry.tag = constants::DW_TAG_inlined_subroutine;
        entry.function_kind = FunctionDieKind::InlineInstance;
        entry
    }

    fn build_origin_backed_entry_value_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let mut line = LineProgram::new(
            encoding,
            gimli::LineEncoding::default(),
            gimli::write::LineString::String(b"/src".to_vec()),
            None,
            gimli::write::LineString::String(b"main.c".to_vec()),
            None,
        );
        line.begin_sequence(Some(Address::Constant(0x1000)));
        line.generate_row();
        line.end_sequence(1);
        let unit_id = dwarf.units.add(Unit::new(encoding, line));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut origin_param_loc = WriteExpression::new();
        origin_param_loc.op_entry_value(inner);
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(origin_param_loc),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_origin_backed_entry_value_override_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_override_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut origin_param_loc = WriteExpression::new();
        origin_param_loc.op_entry_value(inner);
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(origin_param_loc),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let concrete_param_id = unit.add(concrete_id, constants::DW_TAG_formal_parameter);
        let concrete_param = unit.get_mut(concrete_param_id);
        concrete_param.set(
            constants::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(origin_param_id),
        );
        let mut concrete_param_loc = WriteExpression::new();
        concrete_param_loc.op_reg(Register(6));
        concrete_param.set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(concrete_param_loc),
        );

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_origin_backed_entry_value_range_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_range_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut direct_loc = WriteExpression::new();
        direct_loc.op_reg(Register(5));
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut entry_value_loc = WriteExpression::new();
        entry_value_loc.op_entry_value(inner);
        let loc_id = unit.locations.add(LocationList(vec![
            Location::StartEnd {
                begin: Address::Constant(0x1470),
                end: Address::Constant(0x1477),
                data: direct_loc,
            },
            Location::StartEnd {
                begin: Address::Constant(0x1477),
                end: Address::Constant(0x147b),
                data: entry_value_loc,
            },
        ]));
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::LocationListRef(loc_id),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_origin_backed_default_location_entry_value_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_default_location_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut direct_loc = WriteExpression::new();
        direct_loc.op_reg(Register(5));
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut default_entry_value_loc = WriteExpression::new();
        default_entry_value_loc.op_entry_value(inner);
        let loc_id = unit.locations.add(LocationList(vec![
            Location::DefaultLocation {
                data: default_entry_value_loc,
            },
            Location::StartEnd {
                begin: Address::Constant(0x1470),
                end: Address::Constant(0x147b),
                data: direct_loc,
            },
        ]));
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::LocationListRef(loc_id),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn first_unit(dwarf: &gimli::Dwarf<DwarfReader>) -> gimli::Unit<DwarfReader> {
        let mut units = dwarf.units();
        let header = units.next().unwrap().unwrap();
        dwarf.unit(header).unwrap()
    }

    fn first_parameter_location(
        unit: &gimli::Unit<DwarfReader>,
    ) -> gimli::AttributeValue<DwarfReader> {
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().unwrap() {
            if entry.tag() == constants::DW_TAG_formal_parameter {
                return entry.attr_value(constants::DW_AT_location).unwrap();
            }
        }
        panic!("fixture has no formal parameter");
    }

    #[test]
    fn parameter_loclist_only_delays_entry_when_a_later_location_is_available() {
        let dwarf = build_origin_backed_entry_value_range_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let location = first_parameter_location(&unit);
        assert!(LoadedObjfile::parameter_location_starts_after_entry(
            &dwarf,
            &unit,
            location.clone(),
            0x146f,
            0x147b,
        )
        .unwrap());
        assert!(!LoadedObjfile::parameter_location_starts_after_entry(
            &dwarf,
            &unit,
            location.clone(),
            0x1470,
            0x147b,
        )
        .unwrap());
        assert!(!LoadedObjfile::parameter_location_starts_after_entry(
            &dwarf, &unit, location, 0x147b, 0x1480,
        )
        .unwrap());
    }

    #[test]
    fn parameter_loclist_default_location_keeps_entry_available() {
        let dwarf = build_origin_backed_default_location_entry_value_fixture(
            constants::DW_AT_abstract_origin,
        );
        let unit = first_unit(&dwarf);
        assert!(!LoadedObjfile::parameter_location_starts_after_entry(
            &dwarf,
            &unit,
            first_parameter_location(&unit),
            0x146f,
            0x147b,
        )
        .unwrap());
    }

    fn find_subprogram_with_origin_attr(
        unit: &gimli::Unit<DwarfReader>,
        origin_attr: gimli::DwAt,
    ) -> gimli::UnitOffset {
        let mut tree = unit.entries_tree(None).unwrap();
        let root = tree.root().unwrap();
        let mut children = root.children();

        while let Some(child) = children.next().unwrap() {
            let entry = child.entry();
            if entry.tag() == constants::DW_TAG_subprogram
                && entry.attr_value(origin_attr).is_some()
            {
                return entry.offset();
            }
        }

        panic!("failed to find subprogram with origin attr {origin_attr:?}");
    }

    #[test]
    fn selected_non_inline_ranges_keeps_hot_partition_first_when_cold_has_lower_address() {
        let ranges = [(0x8e97c0, 0x8e9be0), (0x76e78e, 0x76e798)];
        let entry = subprogram_entry(&ranges, None);

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges, None),
            vec![(0x8e97c0, 0x8e9be0)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_keeps_single_contiguous_range() {
        let ranges = [(0x8ea060, 0x8eb07b)];
        let entry = subprogram_entry(&ranges, None);

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges, None),
            vec![(0x8ea060, 0x8eb07b)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_prefers_range_containing_entry_pc() {
        let ranges = [(0x100, 0x180), (0x200, 0x220)];
        let entry = subprogram_entry(&ranges, Some(0x208));

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges, None),
            vec![(0x200, 0x220)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_without_entry_pc_keeps_first_range_even_if_later_range_is_larger()
    {
        let ranges = [(0x100, 0x110), (0x200, 0x260)];
        let entry = subprogram_entry(&ranges, None);

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges, None),
            vec![(0x100, 0x110)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_prefers_range_containing_symbol_start_when_entry_pc_missing() {
        let ranges = [(0x1162, 0x116d), (0x116d, 0x127c), (0x1150, 0x1162)];
        let entry = subprogram_entry(&ranges, None);

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges, Some(0x1150)),
            vec![(0x1150, 0x1162)],
        );
    }

    #[test]
    fn selected_non_inline_probe_address_clamps_prologue_skip_to_function_range() {
        assert_eq!(
            LoadedObjfile::selected_non_inline_probe_address(0x1470, 0x147b, 0x14f2),
            0x1470
        );
        assert_eq!(
            LoadedObjfile::selected_non_inline_probe_address(0x1470, 0x147b, 0x1474),
            0x1474
        );
    }

    #[test]
    fn probe_advance_rejects_control_flow_instructions() {
        for code in [
            &[0x75, 0x02][..],                     // jne
            &[0x0f, 0x84, 0x00, 0x00, 0x00, 0x00], // je near
            &[0xeb, 0x00],                         // jmp short
            &[0xff, 0xe0],                         // jmp rax
            &[0xe2, 0xfe],                         // loop
            &[0xe3, 0x00],                         // jrcxz
            &[0xe8, 0x00, 0x00, 0x00, 0x00],       // call relative
            &[0xff, 0xd0],                         // call rax
            &[0xc3],                               // ret
            &[0xc2, 0x10, 0x00],                   // ret 16
            &[0x0f, 0x05],                         // syscall
            &[0xcc],                               // int3
            &[0x0f, 0x0b],                         // ud2
        ] {
            let mut prefix = vec![0x90];
            prefix.extend_from_slice(code);
            let reason = LoadedObjfile::validate_linear_instructions(&prefix, 0x1000)
                .unwrap_err()
                .to_string();
            assert!(reason.contains("0x1001"), "{code:x?}: {reason}");
        }
    }

    #[test]
    fn probe_advance_decodes_instructions_and_requires_a_complete_prefix() {
        // push rbp; mov rbp,rsp; mov eax,0xc3e8ff75; mov [rbp-4],edi.
        // Branch, call and return opcode bytes inside the immediate are data.
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0xb8, 0x75, 0xff, 0xe8, 0xc3, 0x89, 0x7d, 0xfc,
        ];
        LoadedObjfile::validate_linear_instructions(&code, 0x1000).unwrap();
        assert!(LoadedObjfile::validate_linear_instructions(&code[..11], 0x1000).is_err());
        assert!(LoadedObjfile::validate_linear_instructions(&[0x0f], 0x1000).is_err());
    }

    async fn load_test_module(source: &str) -> anyhow::Result<(tempfile::TempDir, LoadedObjfile)> {
        let dir = tempfile::tempdir()?;
        let source_path = dir.path().join("parameters.c");
        let binary = dir.path().join("parameters");
        std::fs::write(&source_path, source)?;
        let output = std::process::Command::new("cc")
            .args(["-g", "-O0", "-o"])
            .arg(&binary)
            .arg(source_path)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let module = LoadedObjfile::load_parallel(
            crate::core::mapping::ModuleMapping::from_path(binary),
            &[],
            false,
            None,
            None,
        )
        .await?;
        Ok((dir, module))
    }

    #[tokio::test]
    async fn probe_advance_keeps_entry_when_a_prologue_marker_follows_a_branch(
    ) -> anyhow::Result<()> {
        let (_dir, module) = load_test_module(
            "int branch(int x) { if (x < 0) return 1; return 2; }\nint main(void) { return branch(1); }\n"
        ).await?;
        let entry = module
            .lightweight_index
            .read()
            .unwrap()
            .find_dies_by_function_name("branch")[0]
            .clone();
        module.ensure_line_info_for_unit(entry.unit_offset)?;
        let (start, end) = module.resolve_function_ranges(&entry)?[0];
        assert!(module.function_parameters_need_prologue(&entry, start, end)?);
        let candidate = end - 1;
        assert!(module
            .validate_probe_advance(start, candidate)
            .unwrap_err()
            .to_string()
            .contains("control-flow"));
        // Even an explicit prologue_end on only one path must not make a
        // function-name trace miss the other path.
        *module.line_mapping.write().unwrap() =
            crate::index::LineMappingTable::from_entries_with_scoped_manager(
                vec![crate::core::LineEntry {
                    address: candidate,
                    end_address: Some(end),
                    file_path: "/src/parameters.c".into(),
                    file_index: 1,
                    unit_offset: entry.unit_offset,
                    compilation_unit: Arc::from("parameters.c"),
                    line: 1,
                    column: 0,
                    is_stmt: true,
                    prologue_end: true,
                }],
                &module.scoped_file_manager.read().unwrap(),
            );
        assert_eq!(module.compute_addresses_for_entry(&entry), vec![start]);
        Ok(())
    }

    #[tokio::test]
    async fn large_stack_parameters_require_a_bare_nonnegative_fbreg() -> anyhow::Result<()> {
        let (_dir, mut module) = load_test_module("int main(void) { return 0; }\n").await?;
        for (size, offset, indirect, pointer, cfa_base, needs_prologue) in [
            (24, 0, false, false, true, false),
            (24, 16, false, false, true, false),
            (17, 0, false, false, true, false),
            (16, 0, false, false, true, true),
            (8, 0, false, false, true, true),
            (24, -24, false, false, true, true),
            (24, 0, true, false, true, true),
            (24, 0, false, true, true, true),
            (24, 16, false, false, false, true),
        ] {
            let encoding = gimli::Encoding {
                format: Format::Dwarf32,
                version: 4,
                address_size: 8,
            };
            let mut dwarf = WriteDwarf::new();
            let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
            let unit = dwarf.units.get_mut(unit_id);
            let root = unit.root();
            let aggregate = unit.add(root, constants::DW_TAG_structure_type);
            unit.get_mut(aggregate)
                .set(constants::DW_AT_byte_size, WriteAttributeValue::Udata(size));
            let alias = unit.add(root, constants::DW_TAG_typedef);
            unit.get_mut(alias).set(
                constants::DW_AT_type,
                WriteAttributeValue::UnitRef(aggregate),
            );
            let qualifier = unit.add(
                root,
                if pointer {
                    constants::DW_TAG_pointer_type
                } else {
                    constants::DW_TAG_const_type
                },
            );
            unit.get_mut(qualifier)
                .set(constants::DW_AT_type, WriteAttributeValue::UnitRef(alias));
            let function = unit.add(root, constants::DW_TAG_subprogram);
            let mut frame_base = WriteExpression::new();
            if cfa_base {
                frame_base.op(constants::DW_OP_call_frame_cfa);
            } else {
                frame_base.op_reg(Register(6));
            }
            unit.get_mut(function).set(
                constants::DW_AT_frame_base,
                WriteAttributeValue::Exprloc(frame_base),
            );
            let parameter = unit.add(function, constants::DW_TAG_formal_parameter);
            unit.get_mut(parameter).set(
                constants::DW_AT_type,
                WriteAttributeValue::UnitRef(qualifier),
            );
            let mut location = WriteExpression::new();
            location.op_fbreg(offset);
            if indirect {
                location.op_deref();
            }
            unit.get_mut(parameter).set(
                constants::DW_AT_location,
                WriteAttributeValue::Exprloc(location),
            );
            let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
            dwarf.write(&mut sections)?;
            module.dwarf = gimli::Dwarf::load(|id| {
                Ok::<_, gimli::Error>(dwarf_reader_from_arc(Arc::from(
                    sections
                        .get(id)
                        .map(|section| section.slice())
                        .unwrap_or_default(),
                )))
            })?;
            *module.parsed_unit_cache.write().unwrap() = Default::default();
            let unit = first_unit(&module.dwarf);
            let mut entries = unit.entries();
            let function_offset = loop {
                let entry = entries.next_dfs()?.unwrap();
                if entry.tag() == constants::DW_TAG_subprogram {
                    break entry.offset();
                }
            };
            let mut entry = subprogram_entry(&[(0x1000, 0x1100)], None);
            entry.unit_offset = unit.header.debug_info_offset().unwrap();
            entry.die_offset = function_offset;
            assert_eq!(
                module.function_parameters_need_prologue(&entry, 0x1000, 0x1100)?,
                needs_prologue,
                "size={size} offset={offset} indirect={indirect} pointer={pointer} cfa_base={cfa_base}"
            );
        }
        Ok(())
    }

    #[test]
    fn selected_inline_address_prefers_entry_pc_over_cold_min_range() {
        let entry = inline_entry(
            &[
                (0x8eb12b, 0x8eb139),
                (0x8eb150, 0x8eb157),
                (0x8eb16a, 0x8eb1b0),
                (0x76e798, 0x76e7a2),
            ],
            Some(0x8eb16a),
        );

        assert_eq!(
            LoadedObjfile::selected_inline_address(
                &entry,
                &[
                    (0x8eb12b, 0x8eb139),
                    (0x8eb150, 0x8eb157),
                    (0x8eb16a, 0x8eb1b0),
                    (0x76e798, 0x76e7a2),
                ],
                false,
            ),
            Some(0x8eb16a)
        );
    }

    #[test]
    fn selected_inline_address_without_entry_pc_keeps_first_emitted_hot_range() {
        let entry = inline_entry(
            &[
                (0x8eb12b, 0x8eb139),
                (0x8eb150, 0x8eb157),
                (0x76e798, 0x76e7a2),
            ],
            None,
        );

        assert_eq!(
            LoadedObjfile::selected_inline_address(
                &entry,
                &[
                    (0x8eb12b, 0x8eb139),
                    (0x8eb150, 0x8eb157),
                    (0x76e798, 0x76e7a2),
                ],
                false,
            ),
            Some(0x8eb12b)
        );
    }

    #[test]
    fn selected_inline_address_ignores_entry_pc_outside_inline_ranges() {
        let entry = inline_entry(&[(0x1289, 0x1293)], Some(0x1215));

        assert_eq!(
            LoadedObjfile::selected_inline_address(&entry, &[(0x1289, 0x1293)], false),
            Some(0x1289)
        );
    }

    #[test]
    fn selected_inline_address_keeps_line_table_point_entry_before_range() {
        let entry = inline_entry(&[(0x1278, 0x1284)], Some(0x1275));

        assert_eq!(
            LoadedObjfile::selected_inline_address(&entry, &[(0x1278, 0x1284)], true),
            Some(0x1275)
        );
        assert_eq!(
            LoadedObjfile::selected_inline_address(&entry, &[(0x1278, 0x1284)], false),
            Some(0x1278)
        );
    }

    #[test]
    fn selected_inline_address_rejects_distant_line_table_entry_before_range() {
        let entry = inline_entry(&[(0x1289, 0x1293)], Some(0x1215));

        assert_eq!(
            LoadedObjfile::selected_inline_address(&entry, &[(0x1289, 0x1293)], true),
            Some(0x1289)
        );
    }

    #[test]
    fn selected_inline_address_keeps_entry_pc_only_point_scopes() {
        let entry = inline_entry(&[], Some(0x1289));

        assert_eq!(
            LoadedObjfile::selected_inline_address(&entry, &[], false),
            Some(0x1289)
        );
    }

    #[test]
    fn subprogram_uses_entry_value_via_abstract_origin_parameters() {
        let dwarf = build_origin_backed_entry_value_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            LoadedObjfile::direct_formal_parameters_entry_value_state(&dwarf, &unit, &concrete)
                .unwrap(),
            None,
            "concrete DIE should not expose direct parameter children in this fixture"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "entry_value should be discovered through DW_AT_abstract_origin"
        );
    }

    #[test]
    fn local_origins_work_without_reparsing_primary_or_supplementary_line_tables() {
        for supplementary in [false, true] {
            for attr in [
                constants::DW_AT_abstract_origin,
                constants::DW_AT_specification,
            ] {
                let mut dwarf = build_origin_backed_entry_value_fixture(attr);
                let unit = first_unit(&dwarf);
                let concrete = unit
                    .entry(find_subprogram_with_origin_attr(&unit, attr))
                    .unwrap();
                let gimli::AttributeValue::UnitRef(offset) = concrete.attr_value(attr).unwrap()
                else {
                    panic!("expected a local origin reference");
                };
                // A second parse must fail; the already parsed unit remains usable.
                dwarf.debug_line = gimli::DebugLine::from(dwarf_reader_from_arc(Arc::from([])));
                assert!(dwarf.unit(unit.header.clone()).is_err());
                if supplementary {
                    let mut primary = gimli::Dwarf::load(|_| {
                        Ok::<_, gimli::Error>(dwarf_reader_from_arc(Arc::from([])))
                    })
                    .unwrap();
                    primary.set_sup(dwarf);
                    dwarf = primary;
                }
                for reference in [
                    gimli::AttributeValue::UnitRef(offset),
                    gimli::AttributeValue::DebugInfoRef(
                        offset.to_debug_info_offset(&unit.header).unwrap(),
                    ),
                ] {
                    let (_, origin_unit, origin) =
                        crate::semantics::resolve_origin_entry(&dwarf, &unit, reference)
                            .unwrap()
                            .unwrap();
                    assert_eq!(origin.offset(), offset);
                    assert_eq!(
                        crate::semantics::resolve_name_with_origins(&dwarf, &origin_unit, &origin)
                            .unwrap()
                            .as_deref(),
                        Some("entry_value_target")
                    );
                }
                assert_eq!(
                    crate::semantics::resolve_name_with_origins(&dwarf, &unit, &concrete)
                        .unwrap()
                        .as_deref(),
                    Some("entry_value_target")
                );
                assert!(
                    LoadedObjfile::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap()
                );
            }
        }
    }

    #[tokio::test]
    async fn function_queries_reuse_the_cached_unit_across_different_dies() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("functions.c");
        let binary = dir.path().join("functions");
        std::fs::write(&source, "int first(int x) { return x + 1; }\nint second(int x) { return x + 2; }\nint main(void) { return first(second(1)); }\n")?;
        let output = std::process::Command::new("cc")
            .args(["-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut module = LoadedObjfile::load_parallel(
            crate::core::mapping::ModuleMapping::from_path(binary),
            &[],
            false,
            None,
            None,
        )
        .await?;
        let entries = {
            let index = module.lightweight_index.read().unwrap();
            ["first", "second"]
                .into_iter()
                .map(|name| index.find_dies_by_function_name(name)[0].clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(entries[0].unit_offset, entries[1].unit_offset);
        let unit = module.unit(entries[0].unit_offset)?;
        module.dwarf.debug_line = gimli::DebugLine::from(dwarf_reader_from_arc(Arc::from([])));
        assert!(module.dwarf.unit(unit.header.clone()).is_err());
        for entry in entries {
            let ranges = module.resolve_function_ranges(&entry)?;
            assert!(!ranges.is_empty());
            let (start, end) = ranges[0];
            module.function_parameters_need_prologue(&entry, start, end)?;
            assert!(!module.function_uses_entry_value_at(&entry, start)?);
        }
        Ok(())
    }

    #[test]
    fn subprogram_uses_entry_value_via_specification_parameters() {
        let dwarf = build_origin_backed_entry_value_fixture(constants::DW_AT_specification);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_specification);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            LoadedObjfile::direct_formal_parameters_entry_value_state(&dwarf, &unit, &concrete)
                .unwrap(),
            None,
            "concrete DIE should not expose direct parameter children in this fixture"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "entry_value should be discovered through DW_AT_specification"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_does_not_override_concrete_parameter_locations() {
        let dwarf =
            build_origin_backed_entry_value_override_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            LoadedObjfile::direct_formal_parameters_entry_value_state(&dwarf, &unit, &concrete)
                .unwrap(),
            Some(false),
            "concrete DIE should treat its own parameter children as authoritative"
        );
        assert!(
            !LoadedObjfile::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "origin-level entry_value must not override concrete parameter locations"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_only_when_active_location_uses_it() {
        let dwarf = build_origin_backed_entry_value_range_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1474).unwrap(),
            "entry_value should not force the true entry while the active location is still a direct register"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1478)
                .unwrap(),
            "entry_value should still be detected once the active location range switches to it"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_respects_concrete_parameter_overrides() {
        let dwarf =
            build_origin_backed_entry_value_override_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1478)
                .unwrap(),
            "concrete parameter locations must remain authoritative at the selected probe PC"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_prefers_specific_loclist_ranges_over_default_location() {
        let dwarf = build_origin_backed_default_location_entry_value_fixture(
            constants::DW_AT_abstract_origin,
        );
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1474)
                .unwrap(),
            "the specific direct-register range should override the default-location entry_value"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1500)
                .unwrap(),
            "outside the specific range, the default-location entry_value should still apply"
        );
    }

    #[test]
    fn fragment_candidates_match_demangled_function_queries() {
        let mangled = "_ZN2ns6Widget3runEv".to_string();
        let demangled =
            crate::core::demangle::demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), &mangled)
                .unwrap();
        let leaf = crate::core::demangle::demangled_leaf(&demangled);

        let mut functions = HashMap::new();
        functions.insert(
            mangled.clone(),
            vec![IndexEntry {
                name: Arc::<str>::from(mangled.as_str()),
                die_offset: gimli::UnitOffset(0),
                unit_offset: gimli::DebugInfoOffset(0),
                lexical_scope: None,
                tag: constants::DW_TAG_subprogram,
                flags: IndexFlags {
                    is_linkage: true,
                    ..Default::default()
                },
                language: Some(gimli::DW_LANG_C_plus_plus_17),
                representative_addr: Some(0x1000),
                entry_pc: Some(0x1000),
                function_kind: FunctionDieKind::ConcreteSubprogram,
            }],
        );

        let ix = LightweightIndex::from_builder_data(functions, HashMap::new(), HashMap::new());
        let entry = ix.entry(0).unwrap();

        assert_eq!(
            ix.function_candidate_indices_by_fragment(&demangled),
            vec![0]
        );
        assert!(LoadedObjfile::candidate_matches_name(
            &demangled, None, entry
        ));
        assert!(LoadedObjfile::candidate_matches_name(&leaf, None, entry));
    }

    #[test]
    fn fragment_candidates_match_rust_v0_demangled_function_queries() {
        let mangled = "_RNvCs73fAdSrgOJL_4test4main".to_string();
        let demangled =
            crate::core::demangle::demangle_by_lang(Some(gimli::DW_LANG_Rust), &mangled).unwrap();

        let mut functions = HashMap::new();
        functions.insert(
            mangled.clone(),
            vec![IndexEntry {
                name: Arc::<str>::from(mangled.as_str()),
                die_offset: gimli::UnitOffset(0),
                unit_offset: gimli::DebugInfoOffset(0),
                lexical_scope: None,
                tag: constants::DW_TAG_subprogram,
                flags: IndexFlags {
                    is_linkage: true,
                    ..Default::default()
                },
                language: Some(gimli::DW_LANG_Rust),
                representative_addr: Some(0x1000),
                entry_pc: Some(0x1000),
                function_kind: FunctionDieKind::ConcreteSubprogram,
            }],
        );

        let ix = LightweightIndex::from_builder_data(functions, HashMap::new(), HashMap::new());

        assert_eq!(
            ix.function_candidate_indices_by_fragment(&demangled),
            vec![0]
        );
    }

    #[test]
    fn address_display_names_control_only_rust_disambiguators() {
        let entry = |name: &str, language| IndexEntry {
            name: Arc::<str>::from(name),
            die_offset: gimli::UnitOffset(0),
            unit_offset: gimli::DebugInfoOffset(0),
            lexical_scope: None,
            tag: constants::DW_TAG_subprogram,
            flags: IndexFlags {
                is_linkage: true,
                ..Default::default()
            },
            language,
            representative_addr: Some(0x1000),
            entry_pc: Some(0x1000),
            function_kind: FunctionDieKind::ConcreteSubprogram,
        };

        let legacy = entry(
            "_ZN22rust_backtrace_program21rust_backtrace_middle17hbd24b59facb94bf3E",
            Some(gimli::DW_LANG_Rust),
        );
        let legacy_concise = function_name_for_display(&legacy, RustSymbolHashDisplay::Hidden);
        assert_eq!(
            legacy_concise,
            "rust_backtrace_program::rust_backtrace_middle"
        );
        let legacy_full = function_name_for_display(&legacy, RustSymbolHashDisplay::Shown);
        assert!(legacy_full.ends_with("::hbd24b59facb94bf3"));

        let v0 = entry("_RNvCs73fAdSrgOJL_4test4main", Some(gimli::DW_LANG_Rust));
        assert_eq!(
            function_name_for_display(&v0, RustSymbolHashDisplay::Hidden),
            "test::main"
        );
        let v0_full = function_name_for_display(&v0, RustSymbolHashDisplay::Shown);
        assert!(
            v0_full.starts_with("test[") && v0_full.ends_with("::main"),
            "unexpected Rust v0 display name: {v0_full}"
        );

        let cpp = entry("_ZN2ns6Widget3runEv", Some(gimli::DW_LANG_C_plus_plus_17));
        assert_eq!(
            function_name_for_display(&cpp, RustSymbolHashDisplay::Hidden),
            cpp.name.as_ref()
        );
        assert_eq!(
            function_name_for_display(&cpp, RustSymbolHashDisplay::Shown),
            cpp.name.as_ref()
        );
    }

    #[test]
    fn inline_display_names_control_rust_disambiguators_and_preserve_fallbacks() {
        let v0 = "_RNvCs73fAdSrgOJL_4test4main";
        assert_eq!(
            inline_function_name_for_display(
                Some(v0),
                Some("test::main"),
                RustSymbolHashDisplay::Hidden,
            )
            .as_deref(),
            Some("test::main")
        );
        let full = inline_function_name_for_display(
            Some(v0),
            Some("test::main"),
            RustSymbolHashDisplay::Shown,
        )
        .expect("v0 inline symbol should demangle");
        assert!(full.starts_with("test[") && full.ends_with("::main"));

        assert_eq!(
            inline_function_name_for_display(
                Some("_ZN2ns6Widget3runEv"),
                Some("ns::Widget::run"),
                RustSymbolHashDisplay::Shown,
            )
            .as_deref(),
            Some("ns::Widget::run")
        );
        assert_eq!(
            inline_function_name_for_display(
                None,
                Some("plain_inline"),
                RustSymbolHashDisplay::Shown,
            )
            .as_deref(),
            Some("plain_inline")
        );
    }

    #[test]
    fn scan_fallback_matches_substitution_heavy_cpp_queries() {
        let mangled = "_ZNSt6vectorIiSaIiEE3endEv".to_string();
        let demangled =
            crate::core::demangle::demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), &mangled)
                .unwrap();

        let mut functions = HashMap::new();
        functions.insert(
            mangled.clone(),
            vec![IndexEntry {
                name: Arc::<str>::from(mangled.as_str()),
                die_offset: gimli::UnitOffset(0),
                unit_offset: gimli::DebugInfoOffset(0),
                lexical_scope: None,
                tag: constants::DW_TAG_subprogram,
                flags: IndexFlags {
                    is_linkage: true,
                    ..Default::default()
                },
                language: Some(gimli::DW_LANG_C_plus_plus_17),
                representative_addr: Some(0x1000),
                entry_pc: Some(0x1000),
                function_kind: FunctionDieKind::ConcreteSubprogram,
            }],
        );

        let ix = LightweightIndex::from_builder_data(functions, HashMap::new(), HashMap::new());

        assert!(ix
            .function_candidate_indices_by_fragment(&demangled)
            .is_empty());
        assert_eq!(
            LoadedObjfile::scan_matching_candidate_indices(&ix, &demangled, |tag| matches!(
                tag,
                constants::DW_TAG_subprogram | constants::DW_TAG_inlined_subroutine
            )),
            vec![0]
        );
    }
}

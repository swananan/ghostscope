use super::*;

mod btree;
mod hash_table;
mod indirect;
mod nested;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ComplexFormatArgLayout {
    header_len: usize,
    reserved_len: usize,
}

struct ComplexFormatLayout {
    arg_count: u8,
    args: Vec<ComplexFormatArgLayout>,
    inst_data_size: usize,
    total_size: usize,
}

#[derive(Clone, Copy)]
struct ComplexFormatArgPointers<'ctx> {
    status_ptr: PointerValue<'ctx>,
    var_data_ptr: PointerValue<'ctx>,
}

#[derive(Clone, Copy)]
enum RingCaptureLengthKind {
    Explicit,
    End,
}

#[derive(Clone, Copy)]
struct RingCaptureConfig {
    start_offset: u64,
    start_access_size: ghostscope_dwarf::MemoryAccessSize,
    capacity_offset: u64,
    capacity_access_size: ghostscope_dwarf::MemoryAccessSize,
    length_kind: RingCaptureLengthKind,
}

#[derive(Clone, Copy)]
enum IndirectCaptureShape {
    Bytes,
    Sequence {
        element_stride: u64,
        max_elements: usize,
        ring: Option<RingCaptureConfig>,
    },
}

impl IndirectCaptureShape {
    fn prefix_len(self) -> usize {
        match self {
            Self::Bytes => ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE,
            Self::Sequence { .. } => ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE,
        }
    }

    fn reservation_factor(self) -> usize {
        match self {
            Self::Sequence { ring: Some(_), .. } => 2,
            Self::Bytes | Self::Sequence { ring: None, .. } => 1,
        }
    }
}

#[derive(Clone, Copy)]
struct IndirectCaptureConfig {
    data_offset: u64,
    data_access_size: ghostscope_dwarf::MemoryAccessSize,
    length_offset: u64,
    length_access_size: ghostscope_dwarf::MemoryAccessSize,
    excluded_tail_bytes: u64,
    max_len: usize,
    shape: IndirectCaptureShape,
}

#[derive(Clone, Copy)]
struct HashTableCaptureConfig {
    control_offset: u64,
    control_access_size: ghostscope_dwarf::MemoryAccessSize,
    length_offset: u64,
    length_access_size: ghostscope_dwarf::MemoryAccessSize,
    bucket_mask_offset: u64,
    bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize,
    entry_stride: u64,
    occupancy: ghostscope_dwarf::HashTableOccupancy,
    buckets: HashTableBucketSource,
    bucket_order: ghostscope_dwarf::HashTableBucketOrder,
    max_buckets: usize,
}

#[derive(Clone, Copy)]
struct BTreeCaptureConfig {
    root_pointer_offset: u64,
    root_pointer_access_size: ghostscope_dwarf::MemoryAccessSize,
    root_height_offset: u64,
    root_height_access_size: ghostscope_dwarf::MemoryAccessSize,
    length_offset: u64,
    length_access_size: ghostscope_dwarf::MemoryAccessSize,
    node_length_offset: u64,
    node_length_access_size: ghostscope_dwarf::MemoryAccessSize,
    keys: BTreeArraySource,
    values: Option<BTreeArraySource>,
    edges: BTreeEdgesSource,
    node_capacity: u64,
    max_nodes: usize,
}

struct BTreeBulkRead<'ctx, 'name> {
    destination_offset: usize,
    source_address: IntValue<'ctx>,
    length: IntValue<'ctx>,
    max_len: usize,
    name: &'name str,
}

fn complex_format_arg_header_len(arg: &ComplexArg<'_>) -> usize {
    PRINT_COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN + arg.access_path.len()
}

fn complex_format_static_payload_len(arg: &ComplexArg<'_>) -> Option<usize> {
    match &arg.source {
        ComplexArgSource::ImmediateBytes { bytes } => Some(bytes.len()),
        ComplexArgSource::AddressValue { .. } => Some(8),
        ComplexArgSource::ComputedAddress { .. } => Some(8),
        ComplexArgSource::RuntimeRead { .. } => {
            Some(std::cmp::max(arg.data_len, VARIABLE_READ_ERROR_PAYLOAD_LEN))
        }
        ComplexArgSource::ComputedInt { byte_len, .. } => Some(*byte_len),
        ComplexArgSource::MemDump { len, .. } => {
            Some(std::cmp::max(*len, VARIABLE_READ_ERROR_PAYLOAD_LEN))
        }
        ComplexArgSource::ProjectedView { .. } => {
            Some(std::cmp::max(arg.data_len, VARIABLE_READ_ERROR_PAYLOAD_LEN))
        }
        ComplexArgSource::NestedValue { .. } => None,
        ComplexArgSource::MemDumpDynamic { .. } => None,
        ComplexArgSource::IndirectBytes { .. } => None,
        ComplexArgSource::IndirectSequence { .. } => None,
        ComplexArgSource::IndirectRingSequence { .. } => None,
        ComplexArgSource::IndirectHashTable { .. } => None,
        ComplexArgSource::IndirectBTree { .. } => None,
    }
}

fn indirect_capture_capacity(
    reserved_len: usize,
    max_len: usize,
    shape: IndirectCaptureShape,
) -> usize {
    reserved_len
        .saturating_sub(shape.prefix_len())
        .checked_div(shape.reservation_factor())
        .unwrap_or(0)
        .min(max_len)
}

fn plan_complex_format_layout(
    max_trace_event_size: usize,
    bytes_reserved_so_far: usize,
    complex_args: &[ComplexArg<'_>],
) -> ComplexFormatLayout {
    let instruction_budget =
        print_complex_format_instruction_budget(max_trace_event_size, bytes_reserved_so_far);
    let fixed_overhead =
        std::mem::size_of::<InstructionHeader>() + std::mem::size_of::<PrintComplexFormatData>();

    let mut arg_count = 0u8;
    let mut headers_total = 0usize;
    let mut static_payload_total = 0usize;
    let mut dynamic_max_lens = Vec::new();
    let mut arg_payload_plans = Vec::with_capacity(complex_args.len());

    for arg in complex_args {
        let header_len = complex_format_arg_header_len(arg);
        headers_total += header_len;

        let static_payload_len = complex_format_static_payload_len(arg);
        let atomic_dynamic_payload_len = match &arg.source {
            ComplexArgSource::NestedValue { value, .. } => Some(value.total_len),
            _ => None,
        };
        if let Some(payload_len) = static_payload_len {
            static_payload_total += payload_len;
        } else if let ComplexArgSource::MemDumpDynamic { max_len, .. } = &arg.source {
            dynamic_max_lens.push(*max_len);
        } else if let ComplexArgSource::IndirectBytes { max_len, .. } = &arg.source {
            dynamic_max_lens.push(
                ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE.saturating_add(*max_len),
            );
        } else if let ComplexArgSource::IndirectSequence { max_len, .. } = &arg.source {
            dynamic_max_lens
                .push(ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE.saturating_add(*max_len));
        } else if let ComplexArgSource::IndirectRingSequence { max_len, .. } = &arg.source {
            // The verifier cannot relate a second helper's destination offset to
            // its length. An unused payload-sized tail gives both independent
            // bounds enough map headroom; user space ignores the padding.
            dynamic_max_lens.push(
                ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE
                    .saturating_add(max_len.saturating_mul(2)),
            );
        } else if let ComplexArgSource::IndirectHashTable { max_len, .. } = &arg.source {
            dynamic_max_lens
                .push(ghostscope_protocol::HASH_TABLE_HEADER_SIZE.saturating_add(*max_len));
        } else if let ComplexArgSource::IndirectBTree { max_len, .. } = &arg.source {
            dynamic_max_lens.push(ghostscope_protocol::BTREE_HEADER_SIZE.saturating_add(*max_len));
        } else if let ComplexArgSource::NestedValue { value, .. } = &arg.source {
            dynamic_max_lens.push(value.total_len);
        }

        arg_payload_plans.push((header_len, static_payload_len, atomic_dynamic_payload_len));
        arg_count = arg_count.saturating_add(1);
    }

    // Static payload keeps its existing layout; dynamic payload shares the remaining
    // instruction budget fairly so later {:s.*}/{:x.*} arguments do not get starved.
    let remaining_for_payload = instruction_budget
        .saturating_sub(fixed_overhead)
        .saturating_sub(headers_total)
        .saturating_sub(static_payload_total);
    let dynamic_reservations =
        allocate_dynamic_payload_reservations(&dynamic_max_lens, remaining_for_payload);
    let mut dynamic_reservations_iter = dynamic_reservations.into_iter();

    let args = arg_payload_plans
        .into_iter()
        .map(
            |(header_len, static_payload_len, atomic_dynamic_payload_len)| {
                let reserved_len = static_payload_len
                    .unwrap_or_else(|| dynamic_reservations_iter.next().unwrap_or(0));
                // Nested sidecars use fixed offsets in their registered presentation.
                // A partial reservation cannot be decoded safely, and the emitter
                // already represents an omitted nested payload as Truncated.
                let reserved_len = match atomic_dynamic_payload_len {
                    Some(required_len) if reserved_len < required_len => 0,
                    _ => reserved_len,
                };
                ComplexFormatArgLayout {
                    header_len,
                    reserved_len,
                }
            },
        )
        .collect::<Vec<_>>();

    let total_args_payload = args
        .iter()
        .map(|arg_layout| arg_layout.header_len + arg_layout.reserved_len)
        .sum::<usize>();
    let inst_data_size = std::mem::size_of::<PrintComplexFormatData>() + total_args_payload;
    let total_size = std::mem::size_of::<InstructionHeader>() + inst_data_size;

    ComplexFormatLayout {
        arg_count,
        args,
        inst_data_size,
        total_size,
    }
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Compile formatted print statement: collect all variable data and send as PrintComplexFormat instruction
    pub(super) fn resolve_memory_format_address(
        &mut self,
        expr: &crate::script::ast::Expr,
    ) -> Result<RuntimeAddress<'ctx>> {
        if let Ok(addr) = self.resolve_runtime_address_from_expr(expr) {
            return Ok(addr);
        }

        let dwarf_error = match self.query_dwarf_for_complex_expr(expr) {
            Ok(Some(var)) => {
                let pc_address = self.get_compile_time_context()?.pc_address;
                return self.variable_read_plan_to_runtime_address(&var, pc_address, None);
            }
            Ok(None) => None,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "DWARF address resolution unavailable for memory format expression; trying script value fallback"
                );
                Some(err)
            }
        };

        match self.compile_expr(expr)? {
            BasicValueEnum::PointerValue(pv) => self
                .builder
                .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                .map(|value| RuntimeAddress::available(value, self.context))
                .map_err(|e| CodeGenError::Builder(e.to_string())),
            _ => {
                Err(dwarf_error
                    .unwrap_or_else(|| CodeGenError::VariableNotFound(format!("{expr:?}"))))
            }
        }
    }

    pub(super) fn compile_formatted_print(
        &mut self,
        format: &str,
        args: &[crate::script::ast::Expr],
    ) -> Result<u16> {
        info!(
            "Compiling formatted print: '{}' with {} arguments",
            format,
            args.len()
        );
        let format_string_index = self.trace_context.add_string(format.to_string())?;
        let template = FormatTemplate::parse(format)
            .map_err(|error| CodeGenError::TypeError(error.to_string()))?;
        let mut complex_args: Vec<ComplexArg<'ctx>> =
            Vec::with_capacity(template.wire_argument_count());
        let mut ai = 0usize; // arg cursor
        for slot in template.slots() {
            match slot.conversion {
                FormatConversion::Default => {
                    if ai >= args.len() {
                        break;
                    }
                    let expr = &args[ai];
                    let a = self.compile_print_expr_with_builtin_exprerror(expr, |ctx| {
                        ctx.resolve_expr_to_arg(expr)
                    })?;
                    complex_args.push(a);
                    ai += 1;
                }
                FormatConversion::Pointer => {
                    if ai >= args.len() {
                        break;
                    }
                    // Force pointer address payload (u64) regardless of DWARF shape
                    let expr = &args[ai];
                    if let Ok(address) = self.resolve_runtime_address_from_expr(expr) {
                        complex_args.push(ComplexArg {
                            var_name_index: self
                                .trace_context
                                .add_variable_name(self.expr_to_name(expr))?,
                            type_index: self
                                .add_synthesized_type_index_for_kind(TypeKind::Pointer)?,
                            access_path: Vec::new(),
                            data_len: 8,
                            source: ComplexArgSource::ComputedAddress { address },
                        });
                        ai += 1;
                        continue;
                    }

                    // Try compile to IntValue or PointerValue
                    let val = self.compile_expr(expr)?;
                    let iv = match val {
                        BasicValueEnum::IntValue(iv) => iv,
                        BasicValueEnum::PointerValue(pv) => self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                        _ => self
                            .compile_dwarf_expression(expr)
                            .and_then(|bv| match bv {
                                BasicValueEnum::IntValue(iv) => Ok(iv),
                                BasicValueEnum::PointerValue(pv) => self
                                    .builder
                                    .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                                    .map_err(|e| CodeGenError::Builder(e.to_string())),
                                _ => Err(CodeGenError::TypeError("pointer expected".into())),
                            })?,
                    };
                    complex_args.push(ComplexArg {
                        var_name_index: self
                            .trace_context
                            .add_variable_name(self.expr_to_name(expr))?,
                        type_index: self.add_synthesized_type_index_for_kind(TypeKind::Pointer)?,
                        access_path: Vec::new(),
                        data_len: 8,
                        source: ComplexArgSource::ComputedInt {
                            value: iv,
                            byte_len: 8,
                        },
                    });
                    ai += 1;
                }
                FormatConversion::LowerHex
                | FormatConversion::UpperHex
                | FormatConversion::String => {
                    // Memory dump; handle static length at compile time. Other cases use default read and let user space trim.
                    // Handle star: consume length arg (as computed int) then value arg
                    match &slot.length {
                        FormatLength::Static(n) if ai < args.len() => {
                            let Ok(n) = usize::try_from(*n) else {
                                return Err(CodeGenError::TypeError(format!(
                                    "capture length {n} does not fit this host"
                                )));
                            };
                            // Resolve value expr address
                            let expr = &args[ai];
                            let addr_iv = self.resolve_memory_format_address(expr)?;
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(expr))?,
                                type_index: self
                                    .trace_context
                                    .add_type(ghostscope_dwarf::TypeInfo::ArrayType {
                                    element_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                                        name: "u8".into(),
                                        size: 1,
                                        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char
                                            .0
                                            as u16,
                                    }),
                                    element_count: Some(n as u64),
                                    total_size: Some(n as u64),
                                })?,
                                access_path: Vec::new(),
                                data_len: n,
                                source: ComplexArgSource::MemDump {
                                    address: addr_iv,
                                    len: n,
                                },
                            });
                            ai += 1;
                        }
                        FormatLength::Dynamic => {
                            // Dynamic length: consume length arg, then create a dynamic mem-dump for value
                            if ai + 1 >= args.len() {
                                break;
                            }
                            // length argument
                            let len_expr = &args[ai];
                            let len_val = self.compile_expr(len_expr)?;
                            let (len_iv, byte_len) = match len_val {
                                BasicValueEnum::IntValue(iv) => (iv, 8usize),
                                _ => {
                                    return Err(CodeGenError::TypeError(
                                        "length must be integer".into(),
                                    ))
                                }
                            };
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name("__len".into())?,
                                type_index: self
                                    .add_synthesized_type_index_for_kind(TypeKind::U64)?,
                                access_path: Vec::new(),
                                data_len: byte_len,
                                source: ComplexArgSource::ComputedInt {
                                    value: len_iv,
                                    byte_len,
                                },
                            });

                            // value expression -> dynamic memdump with cap
                            let val_expr = &args[ai + 1];
                            let addr_iv = self.resolve_memory_format_address(val_expr)?;
                            // Reserve up to configured per-arg cap for dynamic slices
                            let cap = self.compile_options.mem_dump_cap as usize;
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(val_expr))?,
                                type_index: self
                                    .trace_context
                                    .add_type(ghostscope_dwarf::TypeInfo::ArrayType {
                                    element_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                                        name: "u8".into(),
                                        size: 1,
                                        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char
                                            .0
                                            as u16,
                                    }),
                                    element_count: Some(cap as u64),
                                    total_size: Some(cap as u64),
                                })?,
                                access_path: Vec::new(),
                                data_len: cap,
                                source: ComplexArgSource::MemDumpDynamic {
                                    address: addr_iv,
                                    len_value: len_iv,
                                    max_len: cap,
                                },
                            });
                            ai += 2;
                        }
                        FormatLength::Capture(name) => {
                            // Use script variable `name` as length; emit a length argument + a dynamic mem-dump argument
                            if ai >= args.len() {
                                break;
                            }
                            if !self.variable_exists(name) {
                                return Err(CodeGenError::TypeError(format!(
                                    "capture length variable '{name}' not found"
                                )));
                            }
                            // length as computed int
                            let len_val = self.load_variable(name)?;
                            let (len_iv, byte_len) = match len_val {
                                BasicValueEnum::IntValue(iv) => (iv, 8usize),
                                BasicValueEnum::PointerValue(pv) => (
                                    self.builder
                                        .build_ptr_to_int(
                                            pv,
                                            self.context.i64_type(),
                                            "len_ptr_to_i64",
                                        )
                                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                                    8usize,
                                ),
                                _ => {
                                    return Err(CodeGenError::TypeError(
                                        "length must be integer/pointer".into(),
                                    ))
                                }
                            };
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(name.clone())?,
                                type_index: self
                                    .add_synthesized_type_index_for_kind(TypeKind::U64)?,
                                access_path: Vec::new(),
                                data_len: byte_len,
                                source: ComplexArgSource::ComputedInt {
                                    value: len_iv,
                                    byte_len,
                                },
                            });

                            // value
                            let val_expr = &args[ai];
                            let addr_iv = self.resolve_memory_format_address(val_expr)?;
                            let cap = self.compile_options.mem_dump_cap as usize;
                            complex_args.push(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(val_expr))?,
                                type_index: self
                                    .trace_context
                                    .add_type(ghostscope_dwarf::TypeInfo::ArrayType {
                                    element_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                                        name: "u8".into(),
                                        size: 1,
                                        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char
                                            .0
                                            as u16,
                                    }),
                                    element_count: Some(cap as u64),
                                    total_size: Some(cap as u64),
                                })?,
                                access_path: Vec::new(),
                                data_len: cap,
                                source: ComplexArgSource::MemDumpDynamic {
                                    address: addr_iv,
                                    len_value: len_iv,
                                    max_len: cap,
                                },
                            });
                            ai += 1;
                        }
                        _ => {
                            // None: resolve value directly
                            if ai >= args.len() {
                                break;
                            }
                            complex_args.push(self.resolve_expr_to_arg(&args[ai])?);
                            ai += 1;
                        }
                    }
                }
            }
        }
        self.generate_print_complex_format_instruction(format_string_index, &complex_args)?;
        Ok(1)
    }

    fn write_complex_format_instruction_header(
        &mut self,
        buffer: PointerValue<'ctx>,
        format_string_index: u16,
        arg_count: u8,
        inst_data_size: usize,
    ) -> Result<PointerValue<'ctx>> {
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexFormat as u8 as u64, false);
        self.builder
            .build_store(buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // SAFETY: buffer points at a reserved PrintComplexFormat instruction
        // region and the offset is derived from InstructionHeader.
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(INSTRUCTION_HEADER_DATA_LENGTH_OFFSET as u64, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(inst_data_size as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // SAFETY: PrintComplexFormatData starts immediately after InstructionHeader.
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(INSTRUCTION_HEADER_SIZE as u64, false)],
                    "pcf_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get pcf_data_ptr GEP: {e}"))
                })?
        };

        let fsi_ptr = self
            .builder
            .build_pointer_cast(
                data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "fsi_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast fsi_ptr: {e}")))?;
        let fsi_val = self
            .context
            .i16_type()
            .const_int(format_string_index as u64, false);
        self.builder
            .build_store(fsi_ptr, fsi_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store fsi: {e}")))?;

        // SAFETY: arg_count offset is within PrintComplexFormatData.
        let arg_cnt_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(PRINT_COMPLEX_FORMAT_DATA_ARG_COUNT_OFFSET as u64, false)],
                    "arg_count_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get arg_count GEP: {e}")))?
        };
        self.builder
            .build_store(
                arg_cnt_ptr,
                self.context.i8_type().const_int(arg_count as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store arg_count: {e}")))?;

        Ok(data_ptr)
    }

    fn write_complex_format_arg_header(
        &mut self,
        data_ptr: PointerValue<'ctx>,
        offset: usize,
        arg: &ComplexArg<'ctx>,
        reserved_len: usize,
    ) -> Result<ComplexFormatArgPointers<'ctx>> {
        // SAFETY: offset is advanced by the statically computed per-argument
        // payload sizes and remains within the reserved instruction region.
        let arg_base = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    "arg_base",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get arg_base GEP: {e}")))?
        };

        let vni_cast = self
            .builder
            .build_pointer_cast(
                arg_base,
                self.context.ptr_type(AddressSpace::default()),
                "vni_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast vni ptr: {e}")))?;
        self.builder
            .build_store(
                vni_cast,
                self.context
                    .i16_type()
                    .const_int(arg.var_name_index as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store vni: {e}")))?;

        // SAFETY: type_index offset is within the per-argument payload header.
        let ti_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    arg_base,
                    &[self
                        .context
                        .i32_type()
                        .const_int(PRINT_COMPLEX_FORMAT_ARG_TYPE_INDEX_OFFSET as u64, false)],
                    "ti_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get ti GEP: {e}")))?
        };
        let ti_cast = self
            .builder
            .build_pointer_cast(
                ti_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "ti_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast ti ptr: {e}")))?;
        self.builder
            .build_store(
                ti_cast,
                self.context
                    .i16_type()
                    .const_int(arg.type_index as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store ti: {e}")))?;

        // SAFETY: status offset is within the per-argument payload header.
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    arg_base,
                    &[self
                        .context
                        .i32_type()
                        .const_int(PRINT_COMPLEX_FORMAT_ARG_STATUS_OFFSET as u64, false)],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {e}")))?
        };
        self.builder
            .build_store(status_ptr, self.context.i8_type().const_int(0, false))
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

        // SAFETY: access_path_len offset is within the per-argument payload header.
        let access_path_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    arg_base,
                    &[self.context.i32_type().const_int(
                        PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_LEN_OFFSET as u64,
                        false,
                    )],
                    "apl_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get apl GEP: {e}")))?
        };
        self.builder
            .build_store(
                access_path_len_ptr,
                self.context
                    .i8_type()
                    .const_int(arg.access_path.len() as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store apl: {e}")))?;

        for (i, b) in arg.access_path.iter().enumerate() {
            // SAFETY: i is bounded by access_path.len(), which was included in
            // the per-argument reserved payload length.
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(
                            (PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET + i) as u64,
                            false,
                        )],
                        &format!("ap_byte_{i}"),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get ap byte GEP: {e}"))
                    })?
            };
            self.builder
                .build_store(byte_ptr, self.context.i8_type().const_int(*b as u64, false))
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store ap byte: {e}")))?;
        }

        // SAFETY: data_len follows the access path bytes inside the reserved
        // per-argument payload.
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    arg_base,
                    &[self.context.i32_type().const_int(
                        (PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET + arg.access_path.len())
                            as u64,
                        false,
                    )],
                    "dl_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get dl GEP: {e}")))?
        };
        let data_len_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "dl_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast dl ptr: {e}")))?;
        self.builder
            .build_store(
                data_len_cast,
                self.context
                    .i16_type()
                    .const_int(reserved_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;

        // SAFETY: var_data_ptr follows the per-argument header and access path
        // inside the reserved payload.
        let var_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    arg_base,
                    &[self.context.i32_type().const_int(
                        (PRINT_COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN + arg.access_path.len()) as u64,
                        false,
                    )],
                    "var_data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get var_data GEP: {e}")))?
        };

        Ok(ComplexFormatArgPointers {
            status_ptr,
            var_data_ptr,
        })
    }

    fn emit_complex_format_immediate_bytes(
        &mut self,
        var_data_ptr: PointerValue<'ctx>,
        bytes: &[u8],
    ) -> Result<()> {
        for (i, b) in bytes.iter().enumerate() {
            // SAFETY: i is bounded by bytes.len(), and immediate bytes are
            // included in the per-argument reserved payload.
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[self.context.i32_type().const_int(i as u64, false)],
                        &format!("var_byte_{i}"),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get var byte GEP: {e}"))
                    })?
            };
            self.builder
                .build_store(byte_ptr, self.context.i8_type().const_int(*b as u64, false))
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store var byte: {e}")))?;
        }
        Ok(())
    }

    fn emit_complex_format_computed_int(
        &mut self,
        var_data_ptr: PointerValue<'ctx>,
        value: IntValue<'ctx>,
        byte_len: usize,
    ) -> Result<()> {
        // Write computed integer into payload buffer based on requested byte_len.
        // Ensure the destination pointer element type matches the stored value type.
        match byte_len {
            1 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw == 1 {
                    // Bool: zero-extend to keep 0/1 in payload
                    self.builder
                        .build_int_z_extend(value, self.context.i8_type(), "expr_zext_bool_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw < 8 {
                    self.builder
                        .build_int_s_extend(value, self.context.i8_type(), "expr_sext_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 8 {
                    self.builder
                        .build_int_truncate(value, self.context.i8_type(), "expr_trunc_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                self.builder
                    .build_store(var_data_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            2 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw < 16 {
                    self.builder
                        .build_int_s_extend(value, self.context.i16_type(), "expr_sext_i16")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 16 {
                    self.builder
                        .build_int_truncate(value, self.context.i16_type(), "expr_trunc_i16")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i16_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i16_ptr_ty, "expr_i16_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            4 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw < 32 {
                    self.builder
                        .build_int_s_extend(value, self.context.i32_type(), "expr_sext_i32")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 32 {
                    self.builder
                        .build_int_truncate(value, self.context.i32_type(), "expr_trunc_i32")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i32_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i32_ptr_ty, "expr_i32_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            8 => {
                let v64 = if value.get_type().get_bit_width() < 64 {
                    self.builder
                        .build_int_s_extend(value, self.context.i64_type(), "expr_sext")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i64_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i64_ptr_ty, "expr_i64_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v64)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            n => {
                let v64 = if value.get_type().get_bit_width() < 64 {
                    self.builder
                        .build_int_z_extend(value, self.context.i64_type(), "expr_zext_fallback")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                for i in 0..n {
                    let shift = self.context.i64_type().const_int((i * 8) as u64, false);
                    let shifted = self
                        .builder
                        .build_right_shift(v64, shift, false, &format!("expr_shr_{i}"))
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let byte = self
                        .builder
                        .build_int_truncate(
                            shifted,
                            self.context.i8_type(),
                            &format!("expr_byte_{i}"),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // SAFETY: i is bounded by n, the immediate payload size reserved
                    // for this argument.
                    let byte_ptr = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[self.context.i32_type().const_int(i as u64, false)],
                                &format!("expr_byte_ptr_{i}"),
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    };
                    self.builder
                        .build_store(byte_ptr, byte)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    fn emit_complex_format_address_value(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        address: &ghostscope_dwarf::PlannedAddress,
        module_for_offsets: Option<&str>,
    ) -> Result<()> {
        let addr = self.resolve_planned_address(address, Some(status_ptr), module_for_offsets)?;
        let cast_ptr = self
            .builder
            .build_pointer_cast(
                var_data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "addr_store_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(cast_ptr, addr.value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    fn emit_complex_format_computed_address(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        address: &RuntimeAddress<'ctx>,
    ) -> Result<()> {
        let cast_ptr = self
            .builder
            .build_pointer_cast(
                var_data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "computed_addr_store_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(cast_ptr, address.value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let current_fn = self.current_function("compile computed address status")?;
        let ok_block = self
            .context
            .append_basic_block(current_fn, "computed_addr_ok");
        let miss_block = self
            .context
            .append_basic_block(current_fn, "computed_addr_offsets_miss");
        let cont_block = self
            .context
            .append_basic_block(current_fn, "computed_addr_cont");
        self.builder
            .build_conditional_branch(address.offsets_found, ok_block, miss_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(ok_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(miss_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::OffsetsUnavailable as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(cont_block);
        Ok(())
    }

    fn emit_complex_format_memdump(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        address: &RuntimeAddress<'ctx>,
        len: usize,
        reserved_len: usize,
    ) -> Result<()> {
        self.emit_complex_format_memdump_at(
            status_ptr,
            var_data_ptr,
            var_data_ptr,
            address,
            len,
            reserved_len,
        )
    }

    fn emit_complex_format_memdump_at(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        payload_ptr: PointerValue<'ctx>,
        dst_ptr: PointerValue<'ctx>,
        address: &RuntimeAddress<'ctx>,
        len: usize,
        payload_reserved_len: usize,
    ) -> Result<()> {
        // Branchy emitters must leave the builder at their continuation block so
        // the caller can append the next formatted argument.
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let i64_ty = self.context.i64_type();
        let i32_ty = self.context.i32_type();

        let dst_ptr = self
            .builder
            .build_pointer_cast(dst_ptr, ptr_ty, "md_dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let base_src_ptr = self
            .builder
            .build_int_to_ptr(address.value, ptr_ty, "md_src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let offsets_found = address.offsets_found;
        let not_found = self
            .builder
            .build_not(offsets_found, "md_offsets_miss")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let null_ptr = ptr_ty.const_null();
        let src_ptr = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                base_src_ptr.into(),
                null_ptr.into(),
                "md_src_or_null",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_pointer_value();
        let len_const = i32_ty.const_int(len as u64, false);
        let zero_i32 = i32_ty.const_zero();
        let effective_len = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                len_const.into(),
                zero_i32.into(),
                "md_len_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let ret = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[dst_ptr.into(), effective_len.into(), src_ptr.into()],
                i64_ty.into(),
                "probe_read_user_memdump",
            )?
            .into_int_value();

        let ok_pred = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, ret, i64_ty.const_zero(), "md_ok")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let ok = self
            .builder
            .build_and(ok_pred, offsets_found, "md_ok_with_offsets")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let func = self.current_function("compile memdump status branch")?;
        let ok_b = self.context.append_basic_block(func, "md_ok");
        let err_b = self.context.append_basic_block(func, "md_err");
        let cont_b = self.context.append_basic_block(func, "md_cont");
        self.builder
            .build_conditional_branch(ok, ok_b, err_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(ok_b);
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(err_b);
        let offsets_err_b = self.context.append_basic_block(func, "md_offsets_err");
        let helper_err_b = self.context.append_basic_block(func, "md_helper_err");
        self.builder
            .build_conditional_branch(not_found, offsets_err_b, helper_err_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(offsets_err_b);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::OffsetsUnavailable as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(helper_err_b);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.emit_complex_format_read_error_payload(
            payload_ptr,
            payload_reserved_len,
            ret,
            address.value,
        )?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(cont_b);
        Ok(())
    }

    fn emit_complex_format_memdump_dynamic(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        address: &RuntimeAddress<'ctx>,
        len_value: IntValue<'ctx>,
        reserved_len: usize,
    ) -> Result<()> {
        // Branchy emitters must leave the builder at their continuation block so
        // the caller can append the next formatted argument.
        let eff_max_len = reserved_len as u32;
        let i32_ty = self.context.i32_type();
        let rlen_i32 = if len_value.get_type().get_bit_width() > 32 {
            self.builder
                .build_int_truncate(len_value, i32_ty, "mdd_len_trunc")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else if len_value.get_type().get_bit_width() < 32 {
            self.builder
                .build_int_z_extend(len_value, i32_ty, "mdd_len_zext")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            len_value
        };

        let zero_i32 = i32_ty.const_zero();
        let is_neg = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::SLT,
                rlen_i32,
                zero_i32,
                "mdd_len_neg",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rlen_nn = self
            .builder
            .build_select(is_neg, zero_i32, rlen_i32, "mdd_len_nn")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();

        let max_const = i32_ty.const_int(eff_max_len as u64, false);
        let gt = self
            .builder
            .build_int_compare(inkwell::IntPredicate::UGT, rlen_nn, max_const, "mdd_gt")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let sel_len = self
            .builder
            .build_select(gt, max_const, rlen_nn, "mdd_rlen")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();

        let func = self.current_function("compile memdump dynamic length branch")?;
        let zero_b = self.context.append_basic_block(func, "mdd_len_zero");
        let read_b = self.context.append_basic_block(func, "mdd_len_read");
        let cont_b = self.context.append_basic_block(func, "mdd_cont");
        let is_zero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                sel_len,
                i32_ty.const_zero(),
                "mdd_len_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_zero, zero_b, read_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(zero_b);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ZeroLength as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(read_b);
        let dst_ptr = self
            .builder
            .build_bit_cast(
                var_data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "mdd_dst_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let base_src_ptr = self
            .builder
            .build_int_to_ptr(address.value, ptr_ty, "mdd_src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let offsets_found = address.offsets_found;
        let not_found = self
            .builder
            .build_not(offsets_found, "mdd_dyn_offsets_miss")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let null_ptr = ptr_ty.const_null();
        let src_ptr = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                base_src_ptr.into(),
                null_ptr.into(),
                "mdd_src_or_null",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_pointer_value();
        let zero_i32 = self.context.i32_type().const_zero();
        let effective_len = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                sel_len.into(),
                zero_i32.into(),
                "mdd_len_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let ret = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[dst_ptr, effective_len.into(), src_ptr.into()],
                self.context.i64_type().into(),
                "probe_read_user_dyn",
            )?
            .into_int_value();
        let ok_pred = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                ret,
                self.context.i64_type().const_zero(),
                "mdd_ok",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let ok = self
            .builder
            .build_and(ok_pred, offsets_found, "mdd_ok_with_offsets")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ok_b = self.context.append_basic_block(func, "mdd_ok");
        let err_b = self.context.append_basic_block(func, "mdd_err");
        self.builder
            .build_conditional_branch(ok, ok_b, err_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(ok_b);
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(err_b);
        let offsets_err_b = self.context.append_basic_block(func, "mdd_offsets_err");
        let helper_err_b = self.context.append_basic_block(func, "mdd_helper_err");
        self.builder
            .build_conditional_branch(not_found, offsets_err_b, helper_err_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(offsets_err_b);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::OffsetsUnavailable as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(helper_err_b);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        if eff_max_len as usize
            >= VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET + std::mem::size_of::<i32>()
        {
            // SAFETY: var_data_ptr points at the read-error payload.
            let errno_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[self
                            .context
                            .i32_type()
                            .const_int(VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET as u64, false)],
                        "mdd_errno_ptr_i8",
                    )
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            let errno_ptr = self
                .builder
                .build_pointer_cast(
                    errno_ptr_i8,
                    self.context.ptr_type(AddressSpace::default()),
                    "mdd_errno_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let errno = self.build_errno_i32(ret, "mdd_errno_i32")?;
            self.builder
                .build_store(errno_ptr, errno)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        }
        if eff_max_len as usize >= VARIABLE_READ_ERROR_PAYLOAD_LEN {
            // SAFETY: eff_max_len is at least the read-error payload length.
            let addr_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[self
                            .context
                            .i32_type()
                            .const_int(VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET as u64, false)],
                        "mdd_addr_ptr_i8",
                    )
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            let addr_ptr = self
                .builder
                .build_pointer_cast(
                    addr_ptr_i8,
                    self.context.ptr_type(AddressSpace::default()),
                    "mdd_addr_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(addr_ptr, address.value)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        }
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_b)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(cont_b);
        Ok(())
    }

    fn emit_complex_format_read_error_payload(
        &mut self,
        var_data_ptr: PointerValue<'ctx>,
        reserved_len: usize,
        helper_result: IntValue<'ctx>,
        address: IntValue<'ctx>,
    ) -> Result<()> {
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let errno_end = VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET + std::mem::size_of::<i32>();
        if reserved_len >= errno_end {
            // SAFETY: the reserved payload includes the errno field.
            let errno_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[i32_type
                            .const_int(VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET as u64, false)],
                        "indirect_errno_ptr_i8",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let errno_ptr = self
                .builder
                .build_pointer_cast(errno_ptr_i8, ptr_type, "indirect_errno_ptr")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let errno = self.build_errno_i32(helper_result, "indirect_errno_i32")?;
            self.builder
                .build_store(errno_ptr, errno)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }

        if reserved_len >= VARIABLE_READ_ERROR_PAYLOAD_LEN {
            // SAFETY: the reserved payload includes the address field.
            let addr_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[i32_type
                            .const_int(VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET as u64, false)],
                        "indirect_addr_ptr_i8",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let addr_ptr = self
                .builder
                .build_pointer_cast(addr_ptr_i8, ptr_type, "indirect_addr_ptr")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_store(addr_ptr, address)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }

        Ok(())
    }

    fn select_indirect_metadata_failure(
        &self,
        read: &crate::ebpf::helper_functions::MemoryReadDiagnostics<'ctx>,
        address: IntValue<'ctx>,
        fallback_result: IntValue<'ctx>,
        fallback_address: IntValue<'ctx>,
        name: &str,
    ) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
        let offsets_available = self
            .builder
            .build_not(read.not_found, &format!("{name}_offsets_available"))
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let helper_failed = self
            .builder
            .build_and(
                read.combined_fail,
                offsets_available,
                &format!("{name}_helper_failed"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let result = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                helper_failed,
                read.helper_result.into(),
                fallback_result.into(),
                &format!("{name}_error_result"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let address = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                helper_failed,
                address.into(),
                fallback_address.into(),
                &format!("{name}_error_address"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        Ok((result, address))
    }

    fn emit_complex_format_projected_view(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        fields: &[ProjectedViewFieldSource],
        reserved_len: usize,
    ) -> Result<()> {
        let function = self.current_function("compile projected semantic view")?;
        let finish_block = self
            .context
            .append_basic_block(function, "projected_view_finish");

        if fields.is_empty() {
            self.builder
                .build_unconditional_branch(finish_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder.position_at_end(finish_block);
            return Ok(());
        }

        for (field_index, field) in fields.iter().enumerate() {
            let mut address = *descriptor;
            for (step_index, step) in field.steps.iter().enumerate() {
                match step {
                    ProjectedViewStep::Member { offset } => {
                        if *offset != 0 {
                            let value = self
                                .builder
                                .build_int_add(
                                    address.value,
                                    self.context.i64_type().const_int(*offset, false),
                                    &format!("projected_view_{field_index}_{step_index}_member"),
                                )
                                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                            address = address.with_value(value);
                        }
                    }
                    ProjectedViewStep::Dereference { pointer_size } => {
                        let read = self.generate_memory_read_with_diagnostics(
                            address,
                            *pointer_size,
                            Some(status_ptr),
                            &format!("projected_view_{field_index}_{step_index}_pointer"),
                        )?;
                        let ok = self
                            .builder
                            .build_not(
                                read.combined_fail,
                                &format!("projected_view_{field_index}_{step_index}_ok"),
                            )
                            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                        let ok_block = self.context.append_basic_block(
                            function,
                            &format!("projected_view_{field_index}_{step_index}_pointer_ok"),
                        );
                        let error_block = self.context.append_basic_block(
                            function,
                            &format!("projected_view_{field_index}_{step_index}_pointer_error"),
                        );
                        self.builder
                            .build_conditional_branch(ok, ok_block, error_block)
                            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

                        self.builder.position_at_end(error_block);
                        self.emit_complex_format_read_error_payload(
                            var_data_ptr,
                            reserved_len,
                            read.helper_result,
                            address.value,
                        )?;
                        self.builder
                            .build_unconditional_branch(finish_block)
                            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

                        self.builder.position_at_end(ok_block);
                        address =
                            RuntimeAddress::available(read.value.into_int_value(), self.context);
                    }
                }
            }

            if field.value_len > 0 {
                // SAFETY: output_offset and value_len were validated against
                // the statically reserved projected-view payload.
                let field_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            var_data_ptr,
                            &[self
                                .context
                                .i32_type()
                                .const_int(field.output_offset as u64, false)],
                            &format!("projected_view_{field_index}_output"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                };
                match field.capture {
                    ghostscope_dwarf::ProjectedViewFieldCapture::Value => {
                        self.emit_complex_format_memdump_at(
                            status_ptr,
                            var_data_ptr,
                            field_ptr,
                            &address,
                            field.value_len,
                            reserved_len,
                        )?;
                    }
                    ghostscope_dwarf::ProjectedViewFieldCapture::Address => {
                        self.emit_complex_format_computed_int(
                            field_ptr,
                            address.value,
                            field.value_len,
                        )?;
                    }
                }
            }

            if field_index + 1 == fields.len() {
                self.builder
                    .build_unconditional_branch(finish_block)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                continue;
            }
            if field.value_len == 0 {
                continue;
            }

            let status = self
                .builder
                .build_load(
                    self.context.i8_type(),
                    status_ptr,
                    &format!("projected_view_{field_index}_status"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    status,
                    self.context.i8_type().const_zero(),
                    &format!("projected_view_{field_index}_read_ok"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let next_block = self.context.append_basic_block(
                function,
                &format!("projected_view_{}_next", field_index + 1),
            );
            self.builder
                .build_conditional_branch(ok, next_block, finish_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder.position_at_end(next_block);
        }

        self.builder.position_at_end(finish_block);
        Ok(())
    }

    fn clamp_probe_read_length(
        &mut self,
        length: IntValue<'ctx>,
        max_len: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let max_len = u32::try_from(max_len).map_err(|_| {
            CodeGenError::DwarfError(
                "dynamic capture exceeds the eBPF helper length width".to_string(),
            )
        })?;
        let i32_type = self.context.i32_type();
        if length.get_type() != i32_type {
            return Err(CodeGenError::LLVMError(format!(
                "probe read length must be i32, got {} bits",
                length.get_type().get_bit_width()
            )));
        }

        if max_len == u32::MAX {
            return Ok(length);
        }
        if max_len == 0 {
            return Ok(i32_type.const_zero());
        }

        // The eBPF verifier does not reliably preserve an i64 upper bound
        // through an ALU32 truncation. Repeat the semantic clamp in i32 first.
        let limit = i32_type.const_int(max_len as u64, false);
        let exceeds_limit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                length,
                limit,
                &format!("{name}_exceeds_limit"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let semantic_bound = self
            .builder
            .build_select(
                exceeds_limit,
                limit,
                length,
                &format!("{name}_semantic_bound"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();

        // LLVM can lower min(length, limit) by comparing a temporary register
        // and then copying the original, unbounded register into the helper
        // argument. Older kernel verifiers do not propagate the temporary's
        // range to that sibling copy. Hide the semantic range from generic
        // optimization, then establish it again with verifier-visible ALU32
        // operations. The mask is an identity for every value at or below the
        // semantic limit; the second clamp narrows a non-all-ones mask exactly.
        let passthrough_type = i32_type.fn_type(&[i32_type.into(), i32_type.into()], false);
        let passthrough_name = "llvm.bpf.passthrough.i32.i32";
        let passthrough = self
            .module
            .get_function(passthrough_name)
            .unwrap_or_else(|| {
                self.module
                    .add_function(passthrough_name, passthrough_type, None)
            });
        let sequence = self.next_bpf_passthrough_sequence;
        self.next_bpf_passthrough_sequence = sequence.checked_add(1).ok_or_else(|| {
            CodeGenError::LLVMError("BPF passthrough sequence exhausted".to_string())
        })?;
        let opaque_bound = self
            .builder
            .build_call(
                passthrough,
                &[
                    i32_type.const_int(sequence as u64, false).into(),
                    semantic_bound.into(),
                ],
                &format!("{name}_opaque_bound"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| CodeGenError::LLVMError("BPF passthrough returned void".to_string()))?
            .into_int_value();
        let verifier_mask = u32::MAX >> max_len.leading_zeros();
        let masked_bound = self
            .builder
            .build_and(
                opaque_bound,
                i32_type.const_int(verifier_mask as u64, false),
                &format!("{name}_verifier_masked"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        if verifier_mask == max_len {
            return Ok(masked_bound);
        }

        let masked_exceeds_limit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                masked_bound,
                limit,
                &format!("{name}_masked_exceeds_limit"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder
            .build_select(
                masked_exceeds_limit,
                limit,
                masked_bound,
                &format!("{name}_bounded"),
            )
            .map(|value| value.into_int_value())
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))
    }

    fn store_complex_payload_u64(
        &self,
        data_ptr: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
        name: &str,
    ) -> Result<()> {
        // SAFETY: callers validate that the fixed header field is reserved.
        let field_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    &format!("{name}_ptr_i8"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        let field_ptr = self
            .builder
            .build_pointer_cast(
                field_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{name}_ptr"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder
            .build_store(field_ptr, value)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        Ok(())
    }

    fn emit_complex_format_runtime_read(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        address: &ghostscope_dwarf::PlannedAddress,
        dwarf_type: &ghostscope_dwarf::TypeInfo,
        module_for_offsets: Option<&str>,
        data_len: usize,
    ) -> Result<()> {
        // Branchy emitters must leave the builder at their continuation block so
        // the caller can append the next formatted argument.
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let dst_ptr = self
            .builder
            .build_bit_cast(var_data_ptr, ptr_type, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let size_val = i32_type.const_int(data_len as u64, false);
        let src_addr =
            self.resolve_planned_address(address, Some(status_ptr), module_for_offsets)?;
        let offsets_found = src_addr.offsets_found;
        let current_fn = self.current_function("compile complex variable read")?;
        let cont2_block = self.context.append_basic_block(current_fn, "after_read");
        let skip_block = self.context.append_basic_block(current_fn, "offsets_skip");
        let found_block = self.context.append_basic_block(current_fn, "offsets_found");
        self.builder
            .build_conditional_branch(offsets_found, found_block, skip_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(skip_block);
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont2_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(found_block);
        let src_ptr = self
            .builder
            .build_int_to_ptr(src_addr.value, ptr_type, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let zero64 = i64_type.const_zero();
        let is_null = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, src_addr.value, zero64, "is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let null_block = self.context.append_basic_block(current_fn, "null_deref");
        let read_block = self.context.append_basic_block(current_fn, "read_user");
        self.builder
            .build_conditional_branch(is_null, null_block, read_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont2_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(read_block);
        let ret = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[dst_ptr, size_val.into(), src_ptr.into()],
                i32_type.into(),
                "probe_read_user",
            )?
            .into_int_value();
        let is_err = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::SLT,
                ret,
                i32_type.const_zero(),
                "ret_lt_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let err_block = self.context.append_basic_block(current_fn, "read_err");
        let ok_block = self.context.append_basic_block(current_fn, "read_ok");
        self.builder
            .build_conditional_branch(is_err, err_block, ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(err_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // SAFETY: var_data_ptr points at the read-error payload.
        let errno_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    var_data_ptr,
                    &[i32_type.const_int(VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET as u64, false)],
                    "errno_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get errno gep: {e}")))?
        };
        let i32_ptr = self
            .builder
            .build_pointer_cast(
                errno_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "errno_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast errno ptr: {e}")))?;
        self.builder
            .build_store(i32_ptr, ret)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store errno: {e}")))?;
        // SAFETY: read-error payload reserves enough bytes for the addr field.
        let addr_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    var_data_ptr,
                    &[i32_type.const_int(VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET as u64, false)],
                    "addr_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get addr gep: {e}")))?
        };
        let addr_ptr = self
            .builder
            .build_pointer_cast(
                addr_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "addr_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast addr ptr: {e}")))?;
        self.builder
            .build_store(addr_ptr, src_addr.value)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store addr: {e}")))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont2_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(ok_block);
        if data_len < dwarf_type.size() as usize {
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.mark_any_success()?;
            self.mark_any_fail()?;
        } else {
            self.mark_any_success()?;
        }
        self.builder
            .build_unconditional_branch(cont2_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(cont2_block);
        Ok(())
    }

    fn emit_complex_format_arg_source(
        &mut self,
        arg: &ComplexArg<'ctx>,
        arg_ptrs: ComplexFormatArgPointers<'ctx>,
        reserved_len: usize,
    ) -> Result<()> {
        let status_ptr = arg_ptrs.status_ptr;
        let var_data_ptr = arg_ptrs.var_data_ptr;

        match &arg.source {
            ComplexArgSource::ImmediateBytes { bytes, .. } => {
                self.emit_complex_format_immediate_bytes(var_data_ptr, bytes)
            }
            ComplexArgSource::MemDump { address, len } => self.emit_complex_format_memdump(
                status_ptr,
                var_data_ptr,
                address,
                *len,
                reserved_len,
            ),
            ComplexArgSource::MemDumpDynamic {
                address,
                len_value,
                max_len: _,
            } => self.emit_complex_format_memdump_dynamic(
                status_ptr,
                var_data_ptr,
                address,
                *len_value,
                reserved_len,
            ),
            ComplexArgSource::IndirectBytes {
                descriptor,
                data_offset,
                data_access_size,
                length_offset,
                length_access_size,
                excluded_tail_bytes,
                max_len,
            } => self.emit_complex_format_indirect(
                status_ptr,
                var_data_ptr,
                descriptor,
                reserved_len,
                IndirectCaptureConfig {
                    data_offset: *data_offset,
                    data_access_size: *data_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    excluded_tail_bytes: *excluded_tail_bytes,
                    max_len: *max_len,
                    shape: IndirectCaptureShape::Bytes,
                },
            ),
            ComplexArgSource::IndirectSequence {
                descriptor,
                data_offset,
                data_access_size,
                length_offset,
                length_access_size,
                element_stride,
                max_elements,
                max_len,
            } => self.emit_complex_format_indirect(
                status_ptr,
                var_data_ptr,
                descriptor,
                reserved_len,
                IndirectCaptureConfig {
                    data_offset: *data_offset,
                    data_access_size: *data_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    excluded_tail_bytes: 0,
                    max_len: *max_len,
                    shape: IndirectCaptureShape::Sequence {
                        element_stride: *element_stride,
                        max_elements: *max_elements,
                        ring: None,
                    },
                },
            ),
            ComplexArgSource::IndirectRingSequence {
                descriptor,
                data_offset,
                data_access_size,
                start_offset,
                start_access_size,
                length,
                capacity_offset,
                capacity_access_size,
                element_stride,
                max_elements,
                max_len,
            } => {
                let (length_offset, length_access_size, length_kind) = match length {
                    RingSequenceLengthSource::Explicit {
                        offset,
                        access_size,
                    } => (*offset, *access_size, RingCaptureLengthKind::Explicit),
                    RingSequenceLengthSource::End {
                        offset,
                        access_size,
                    } => (*offset, *access_size, RingCaptureLengthKind::End),
                };
                self.emit_complex_format_indirect(
                    status_ptr,
                    var_data_ptr,
                    descriptor,
                    reserved_len,
                    IndirectCaptureConfig {
                        data_offset: *data_offset,
                        data_access_size: *data_access_size,
                        length_offset,
                        length_access_size,
                        excluded_tail_bytes: 0,
                        max_len: *max_len,
                        shape: IndirectCaptureShape::Sequence {
                            element_stride: *element_stride,
                            max_elements: *max_elements,
                            ring: Some(RingCaptureConfig {
                                start_offset: *start_offset,
                                start_access_size: *start_access_size,
                                capacity_offset: *capacity_offset,
                                capacity_access_size: *capacity_access_size,
                                length_kind,
                            }),
                        },
                    },
                )
            }
            ComplexArgSource::IndirectHashTable {
                descriptor,
                control_offset,
                control_access_size,
                length_offset,
                length_access_size,
                bucket_mask_offset,
                bucket_mask_access_size,
                entry_stride,
                occupancy,
                buckets,
                bucket_order,
                max_buckets,
                max_len: _,
            } => self.emit_complex_format_hash_table(
                status_ptr,
                var_data_ptr,
                descriptor,
                reserved_len,
                HashTableCaptureConfig {
                    control_offset: *control_offset,
                    control_access_size: *control_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    bucket_mask_offset: *bucket_mask_offset,
                    bucket_mask_access_size: *bucket_mask_access_size,
                    entry_stride: *entry_stride,
                    occupancy: *occupancy,
                    buckets: *buckets,
                    bucket_order: *bucket_order,
                    max_buckets: *max_buckets,
                },
            ),
            ComplexArgSource::IndirectBTree {
                descriptor,
                root_pointer_offset,
                root_pointer_access_size,
                root_height_offset,
                root_height_access_size,
                length_offset,
                length_access_size,
                node_length_offset,
                node_length_access_size,
                keys,
                values,
                edges,
                node_capacity,
                max_nodes,
                max_len: _,
            } => self.emit_complex_format_btree(
                status_ptr,
                var_data_ptr,
                descriptor,
                reserved_len,
                BTreeCaptureConfig {
                    root_pointer_offset: *root_pointer_offset,
                    root_pointer_access_size: *root_pointer_access_size,
                    root_height_offset: *root_height_offset,
                    root_height_access_size: *root_height_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    node_length_offset: *node_length_offset,
                    node_length_access_size: *node_length_access_size,
                    keys: *keys,
                    values: *values,
                    edges: *edges,
                    node_capacity: *node_capacity,
                    max_nodes: *max_nodes,
                },
            ),
            ComplexArgSource::ProjectedView { descriptor, fields } => self
                .emit_complex_format_projected_view(
                    status_ptr,
                    var_data_ptr,
                    descriptor,
                    fields,
                    reserved_len,
                ),
            ComplexArgSource::NestedValue { descriptor, value } => self
                .emit_complex_format_nested_value(
                    status_ptr,
                    var_data_ptr,
                    descriptor,
                    value,
                    reserved_len,
                ),
            ComplexArgSource::ComputedInt { value, byte_len } => {
                self.emit_complex_format_computed_int(var_data_ptr, *value, *byte_len)
            }
            ComplexArgSource::RuntimeRead {
                address,
                dwarf_type,
                module_for_offsets,
            } => self.emit_complex_format_runtime_read(
                status_ptr,
                var_data_ptr,
                address,
                dwarf_type,
                module_for_offsets.as_deref(),
                arg.data_len,
            ),
            ComplexArgSource::AddressValue {
                address,
                module_for_offsets,
            } => self.emit_complex_format_address_value(
                status_ptr,
                var_data_ptr,
                address,
                module_for_offsets.as_deref(),
            ),
            ComplexArgSource::ComputedAddress { address } => {
                self.emit_complex_format_computed_address(status_ptr, var_data_ptr, address)
            }
        }
    }

    /// Generate eBPF code for PrintComplexFormat instruction with runtime reads for variables
    pub(super) fn generate_print_complex_format_instruction(
        &mut self,
        format_string_index: u16,
        complex_args: &[ComplexArg<'ctx>],
    ) -> Result<()> {
        let layout = plan_complex_format_layout(
            self.compile_options.max_trace_event_size as usize,
            self.compile_time_event_bytes_upper_bound,
            complex_args,
        );

        // Reserve buffer directly in accumulation buffer to avoid extra copy
        let buffer = self
            .reserve_instruction_region_or_return_zero(layout.total_size as u64)?
            .into_value_after_runtime_returns();

        // Avoid memset; global buffer is zero-initialized
        let data_ptr = self.write_complex_format_instruction_header(
            buffer,
            format_string_index,
            layout.arg_count,
            layout.inst_data_size,
        )?;

        // Start of variable payload after PrintComplexFormatData.
        let mut offset = std::mem::size_of::<PrintComplexFormatData>();
        for (a, arg_layout) in complex_args.iter().zip(layout.args.iter()) {
            let reserved_len = arg_layout.reserved_len;
            let arg_ptrs =
                self.write_complex_format_arg_header(data_ptr, offset, a, reserved_len)?;
            self.emit_complex_format_arg_source(a, arg_ptrs, reserved_len)?;
            offset += arg_layout.header_len + arg_layout.reserved_len;
        }

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }
}

#[cfg(test)]
mod complex_format_layout_tests {
    use super::*;
    use inkwell::context::Context;
    use inkwell::targets::{CodeModel, FileType, RelocMode};
    use inkwell::targets::{Target, TargetTriple};
    use inkwell::OptimizationLevel;

    fn immediate_arg<'ctx>(bytes: &[u8], access_path: Vec<u8>) -> ComplexArg<'ctx> {
        ComplexArg {
            var_name_index: 0,
            type_index: 0,
            access_path,
            data_len: bytes.len(),
            source: ComplexArgSource::ImmediateBytes {
                bytes: bytes.to_vec(),
            },
        }
    }

    fn dynamic_memdump_arg<'ctx>(context: &'ctx Context, max_len: usize) -> ComplexArg<'ctx> {
        ComplexArg {
            var_name_index: 0,
            type_index: 0,
            access_path: Vec::new(),
            data_len: max_len,
            source: ComplexArgSource::MemDumpDynamic {
                address: RuntimeAddress::available(context.i64_type().const_zero(), context),
                len_value: context.i64_type().const_int(max_len as u64, false),
                max_len,
            },
        }
    }

    fn indirect_bytes_arg<'ctx>(context: &'ctx Context, max_len: usize) -> ComplexArg<'ctx> {
        ComplexArg {
            var_name_index: 0,
            type_index: 0,
            access_path: Vec::new(),
            data_len: ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE + max_len,
            source: ComplexArgSource::IndirectBytes {
                descriptor: RuntimeAddress::available(context.i64_type().const_zero(), context),
                data_offset: 0,
                data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                length_offset: 8,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                excluded_tail_bytes: 0,
                max_len,
            },
        }
    }

    fn indirect_sequence_arg<'ctx>(
        context: &'ctx Context,
        element_stride: u64,
        max_elements: usize,
        max_len: usize,
    ) -> ComplexArg<'ctx> {
        ComplexArg {
            var_name_index: 0,
            type_index: 0,
            access_path: Vec::new(),
            data_len: ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE + max_len,
            source: ComplexArgSource::IndirectSequence {
                descriptor: RuntimeAddress::available(context.i64_type().const_zero(), context),
                data_offset: 0,
                data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                length_offset: 8,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                element_stride,
                max_elements,
                max_len,
            },
        }
    }

    fn indirect_ring_sequence_arg<'ctx>(
        context: &'ctx Context,
        element_stride: u64,
        max_elements: usize,
        max_len: usize,
    ) -> ComplexArg<'ctx> {
        ComplexArg {
            var_name_index: 0,
            type_index: 0,
            access_path: Vec::new(),
            data_len: ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE + max_len,
            source: ComplexArgSource::IndirectRingSequence {
                descriptor: RuntimeAddress::available(context.i64_type().const_zero(), context),
                data_offset: 0,
                data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                start_offset: 8,
                start_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                length: RingSequenceLengthSource::Explicit {
                    offset: 16,
                    access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                },
                capacity_offset: 24,
                capacity_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                element_stride,
                max_elements,
                max_len,
            },
        }
    }

    fn nested_value_arg<'ctx>(context: &'ctx Context, total_len: usize) -> ComplexArg<'ctx> {
        let value = NestedValueSource {
            output_type: ghostscope_dwarf::TypeInfo::StructType {
                name: "Nested".to_string(),
                size: total_len as u64,
                members: Vec::new(),
            },
            presentation: ghostscope_dwarf::ValuePresentation::Dwarf,
            root_payload_len: total_len,
            total_len,
            root: NestedValueRootSource::InlineView { len: total_len },
            children: NestedValueChildrenSource::None,
        };
        ComplexArg {
            var_name_index: 0,
            type_index: 0,
            access_path: Vec::new(),
            data_len: total_len,
            source: ComplexArgSource::NestedValue {
                descriptor: RuntimeAddress::available(context.i64_type().const_zero(), context),
                value: Box::new(value),
            },
        }
    }

    fn short_nested_child_emitter_ir() -> String {
        let context = Context::create();
        let options = crate::CompileOptions::default();
        let mut ebpf = EbpfContext::new(&context, "nested_child", Some(0), &options)
            .expect("create eBPF context");
        let function_type = context.i64_type().fn_type(&[], false);
        let function = ebpf
            .module
            .add_function("emit_nested_child", function_type, None);
        let entry = context.append_basic_block(function, "entry");
        ebpf.builder.position_at_end(entry);
        let slot_len = ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE + 1;
        let parent_payload = ebpf
            .builder
            .build_alloca(
                context.i8_type().array_type(slot_len as u32),
                "parent_payload",
            )
            .expect("allocate nested child slot");
        let descriptor =
            RuntimeAddress::available(context.i64_type().const_int(0x1000, false), &context);
        let child = NestedValueSource {
            output_type: ghostscope_dwarf::TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
            },
            presentation: ghostscope_dwarf::ValuePresentation::Dwarf,
            root_payload_len: 1,
            total_len: 1,
            root: NestedValueRootSource::ProjectedValue { offset: 0, len: 1 },
            children: NestedValueChildrenSource::None,
        };

        ebpf.emit_nested_child_slot(parent_payload, 0, &descriptor, &child)
            .expect("emit nested child capture");
        ebpf.builder
            .build_return(Some(&context.i64_type().const_zero()))
            .expect("return from test function");
        ebpf.module.verify().expect("verify generated LLVM IR");

        ebpf.module.print_to_string().to_string()
    }

    fn indirect_hash_table_arg<'ctx>(
        context: &'ctx Context,
        entry_stride: u64,
        max_buckets: usize,
        max_len: usize,
    ) -> ComplexArg<'ctx> {
        ComplexArg {
            var_name_index: 0,
            type_index: 0,
            access_path: Vec::new(),
            data_len: ghostscope_protocol::HASH_TABLE_HEADER_SIZE + max_len,
            source: ComplexArgSource::IndirectHashTable {
                descriptor: RuntimeAddress::available(context.i64_type().const_zero(), context),
                control_offset: 0,
                control_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                length_offset: 8,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                bucket_mask_offset: 16,
                bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                entry_stride,
                occupancy: ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear,
                buckets: HashTableBucketSource::ReverseFromControl,
                bucket_order: ghostscope_dwarf::HashTableBucketOrder::Reverse,
                max_buckets,
                max_len,
            },
        }
    }

    fn indirect_emitter_ir(capture: IndirectCaptureConfig) -> String {
        let context = Context::create();
        let options = crate::CompileOptions::default();
        let ebpf = EbpfContext::new(&context, "indirect", Some(0), &options);
        let mut ebpf = ebpf.expect("create eBPF context");
        let function_type = context.i64_type().fn_type(&[], false);
        let function = ebpf
            .module
            .add_function("emit_indirect", function_type, None);
        let entry = context.append_basic_block(function, "entry");
        ebpf.builder.position_at_end(entry);
        let status_ptr = ebpf
            .builder
            .build_alloca(context.i8_type(), "status")
            .expect("allocate status");
        let reserved_len = VARIABLE_READ_ERROR_PAYLOAD_LEN.max(
            capture.shape.prefix_len().saturating_add(
                capture
                    .max_len
                    .saturating_mul(capture.shape.reservation_factor()),
            ),
        );
        let data_ptr = ebpf
            .builder
            .build_alloca(context.i8_type().array_type(reserved_len as u32), "payload")
            .expect("allocate payload");
        ebpf.builder
            .build_store(status_ptr, context.i8_type().const_zero())
            .expect("initialize status");
        let descriptor_value = context.i64_type().const_int(0x1000, false);
        let descriptor = RuntimeAddress::available(descriptor_value, &context);

        ebpf.emit_complex_format_indirect(status_ptr, data_ptr, &descriptor, reserved_len, capture)
            .expect("emit indirect capture");
        ebpf.builder
            .build_return(Some(&context.i64_type().const_zero()))
            .expect("return from test function");
        ebpf.module.verify().expect("verify generated LLVM IR");

        ebpf.module.print_to_string().to_string()
    }

    fn clamped_probe_read_assembly(max_len: usize) -> String {
        let context = Context::create();
        let options = crate::CompileOptions::default();
        let mut ebpf = EbpfContext::new(&context, "probe_read_bound", Some(0), &options)
            .expect("create eBPF context");
        let i32_type = context.i32_type();
        let i64_type = context.i64_type();
        let ptr_type = context.ptr_type(AddressSpace::default());
        let function_type = i64_type.fn_type(&[i32_type.into()], false);
        let function = ebpf
            .module
            .add_function("probe_read_bound", function_type, None);
        let entry = context.append_basic_block(function, "entry");
        ebpf.builder.position_at_end(entry);
        let length = function
            .get_nth_param(0)
            .expect("length argument")
            .into_int_value();
        let length = ebpf
            .clamp_probe_read_length(length, max_len, "test_probe_read_len")
            .expect("clamp probe read length");
        let result = ebpf
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[
                    ptr_type.const_null().into(),
                    length.into(),
                    ptr_type.const_null().into(),
                ],
                i64_type.into(),
                "test_probe_read",
            )
            .expect("emit probe read")
            .into_int_value();
        ebpf.builder
            .build_return(Some(&result))
            .expect("return probe read result");
        ebpf.module.verify().expect("verify generated LLVM IR");

        Target::initialize_bpf(&Default::default());
        let triple = TargetTriple::create("bpf-pc-linux");
        let target = Target::from_triple(&triple).expect("get BPF target");
        let target_machine = target
            .create_target_machine(
                &triple,
                "generic",
                "+alu32",
                OptimizationLevel::Default,
                RelocMode::PIC,
                CodeModel::Small,
            )
            .expect("create BPF target machine");
        let assembly = target_machine
            .write_to_memory_buffer(&ebpf.module, FileType::Assembly)
            .expect("emit BPF assembly");
        String::from_utf8(assembly.as_slice().to_vec()).expect("BPF assembly is UTF-8")
    }

    fn hash_table_emitter_ir(capture: HashTableCaptureConfig, max_len: usize) -> String {
        let context = Context::create();
        let options = crate::CompileOptions::default();
        let ebpf = EbpfContext::new(&context, "hash_table", Some(0), &options);
        let mut ebpf = ebpf.expect("create eBPF context");
        let function_type = context.i64_type().fn_type(&[], false);
        let function = ebpf
            .module
            .add_function("emit_hash_table", function_type, None);
        let entry = context.append_basic_block(function, "entry");
        ebpf.builder.position_at_end(entry);
        let status_ptr = ebpf
            .builder
            .build_alloca(context.i8_type(), "status")
            .expect("allocate status");
        let reserved_len = ghostscope_protocol::HASH_TABLE_HEADER_SIZE + max_len;
        let data_ptr = ebpf
            .builder
            .build_alloca(context.i8_type().array_type(reserved_len as u32), "payload")
            .expect("allocate payload");
        ebpf.builder
            .build_store(status_ptr, context.i8_type().const_zero())
            .expect("initialize status");
        let descriptor =
            RuntimeAddress::available(context.i64_type().const_int(0x1000, false), &context);

        ebpf.emit_complex_format_hash_table(
            status_ptr,
            data_ptr,
            &descriptor,
            reserved_len,
            capture,
        )
        .expect("emit hash-table capture");
        ebpf.builder
            .build_return(Some(&context.i64_type().const_zero()))
            .expect("return from test function");
        ebpf.module.verify().expect("verify generated LLVM IR");

        ebpf.module.print_to_string().to_string()
    }

    fn nested_hash_table_emitter_ir(
        buckets: HashTableBucketSource,
        occupancy: ghostscope_dwarf::HashTableOccupancy,
    ) -> String {
        let context = Context::create();
        let options = crate::CompileOptions::default();
        let mut ebpf = EbpfContext::new(&context, "nested_hash_table", Some(0), &options)
            .expect("create eBPF context");
        let function_type = context.i64_type().fn_type(&[], false);
        let function = ebpf
            .module
            .add_function("emit_nested_hash_table", function_type, None);
        let entry = context.append_basic_block(function, "entry");
        let finish = context.append_basic_block(function, "finish");
        ebpf.builder.position_at_end(entry);

        let bucket_count = 2usize;
        let entry_stride = 8u64;
        let occupancy_width = usize::try_from(
            occupancy
                .byte_width()
                .expect("test occupancy has a known width"),
        )
        .expect("test occupancy width fits usize");
        let root_payload_len = ghostscope_protocol::HASH_TABLE_HEADER_SIZE
            + bucket_count * (occupancy_width + entry_stride as usize);
        let child = NestedValueSource {
            output_type: ghostscope_dwarf::TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
            },
            presentation: ghostscope_dwarf::ValuePresentation::Dwarf,
            root_payload_len: 1,
            total_len: 1,
            root: NestedValueRootSource::ProjectedValue { offset: 0, len: 1 },
            children: NestedValueChildrenSource::None,
        };
        let bucket_slot_stride =
            ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE + child.total_len;
        let total_len = root_payload_len + bucket_count * bucket_slot_stride;
        let parent_payload = ebpf
            .builder
            .build_alloca(
                context.i8_type().array_type(total_len as u32),
                "parent_payload",
            )
            .expect("allocate nested hash-table payload");
        let descriptor =
            RuntimeAddress::available(context.i64_type().const_int(0x1000, false), &context);
        let control_offset = match buckets {
            HashTableBucketSource::LegacyAfterControl { .. } => 16,
            HashTableBucketSource::Forward { .. } | HashTableBucketSource::ReverseFromControl => 0,
        };
        let fields = [NestedHashTableFieldSource {
            field_index: 0,
            entry_offset: 0,
            slot_offset: 0,
            child: Box::new(child),
        }];
        let metadata = NestedHashTableMetadataSource {
            control_offset,
            control_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            entry_stride,
            occupancy,
            buckets,
        };

        ebpf.emit_nested_hash_table_children(
            parent_payload,
            &descriptor,
            root_payload_len,
            bucket_slot_stride,
            bucket_count,
            &fields,
            &metadata,
            finish,
        )
        .expect("emit nested hash-table capture");
        if ebpf
            .builder
            .get_insert_block()
            .is_some_and(|block| block.get_terminator().is_none())
        {
            ebpf.builder
                .build_unconditional_branch(finish)
                .expect("finish nested hash-table capture");
        }
        ebpf.builder.position_at_end(finish);
        ebpf.builder
            .build_return(Some(&context.i64_type().const_zero()))
            .expect("return from test function");
        ebpf.module.verify().expect("verify generated LLVM IR");

        ebpf.module.print_to_string().to_string()
    }

    fn btree_emitter_ir(capture: BTreeCaptureConfig, max_len: usize) -> String {
        let context = Context::create();
        let options = crate::CompileOptions::default();
        let ebpf = EbpfContext::new(&context, "btree", Some(0), &options);
        let mut ebpf = ebpf.expect("create eBPF context");
        let function_type = context.i64_type().fn_type(&[], false);
        let function = ebpf.module.add_function("emit_btree", function_type, None);
        let entry = context.append_basic_block(function, "entry");
        ebpf.builder.position_at_end(entry);
        let status_ptr = ebpf
            .builder
            .build_alloca(context.i8_type(), "status")
            .expect("allocate status");
        let reserved_len = ghostscope_protocol::BTREE_HEADER_SIZE + max_len;
        let data_ptr = ebpf
            .builder
            .build_alloca(context.i8_type().array_type(reserved_len as u32), "payload")
            .expect("allocate payload");
        ebpf.builder
            .build_store(status_ptr, context.i8_type().const_zero())
            .expect("initialize status");
        let descriptor =
            RuntimeAddress::available(context.i64_type().const_int(0x1000, false), &context);

        ebpf.emit_complex_format_btree(status_ptr, data_ptr, &descriptor, reserved_len, capture)
            .expect("emit B-Tree capture");
        ebpf.builder
            .build_return(Some(&context.i64_type().const_zero()))
            .expect("return from test function");
        ebpf.module.verify().expect("verify generated LLVM IR");

        ebpf.module.print_to_string().to_string()
    }

    fn projected_view_emitter_ir() -> String {
        let context = Context::create();
        let options = crate::CompileOptions::default();
        let ebpf = EbpfContext::new(&context, "projected_view", Some(0), &options);
        let mut ebpf = ebpf.expect("create eBPF context");
        let function_type = context.i64_type().fn_type(&[], false);
        let function = ebpf
            .module
            .add_function("emit_projected_view", function_type, None);
        let entry = context.append_basic_block(function, "entry");
        ebpf.builder.position_at_end(entry);
        let status_ptr = ebpf
            .builder
            .build_alloca(context.i8_type(), "status")
            .expect("allocate status");
        let reserved_len = VARIABLE_READ_ERROR_PAYLOAD_LEN;
        let data_ptr = ebpf
            .builder
            .build_alloca(context.i8_type().array_type(reserved_len as u32), "payload")
            .expect("allocate payload");
        ebpf.builder
            .build_store(status_ptr, context.i8_type().const_zero())
            .expect("initialize status");
        let descriptor =
            RuntimeAddress::available(context.i64_type().const_int(0x1000, false), &context);
        let fields = vec![
            ProjectedViewFieldSource {
                output_offset: 0,
                value_len: 4,
                steps: vec![
                    ProjectedViewStep::Member { offset: 8 },
                    ProjectedViewStep::Dereference {
                        pointer_size: ghostscope_dwarf::MemoryAccessSize::U64,
                    },
                ],
                capture: ghostscope_dwarf::ProjectedViewFieldCapture::Value,
            },
            ProjectedViewFieldSource {
                output_offset: 4,
                value_len: 8,
                steps: vec![
                    ProjectedViewStep::Member { offset: 16 },
                    ProjectedViewStep::Dereference {
                        pointer_size: ghostscope_dwarf::MemoryAccessSize::U64,
                    },
                ],
                capture: ghostscope_dwarf::ProjectedViewFieldCapture::Address,
            },
        ];

        ebpf.emit_complex_format_projected_view(
            status_ptr,
            data_ptr,
            &descriptor,
            &fields,
            reserved_len,
        )
        .expect("emit projected view");
        ebpf.builder
            .build_return(Some(&context.i64_type().const_zero()))
            .expect("return from test function");
        ebpf.module.verify().expect("verify generated LLVM IR");

        ebpf.module.print_to_string().to_string()
    }

    #[test]
    fn complex_format_layout_records_per_arg_lengths() {
        let context = Context::create();
        let args = vec![
            immediate_arg(&[1, 2, 3], vec![7, 8]),
            dynamic_memdump_arg(&context, 64),
        ];

        let layout = plan_complex_format_layout(4096, 0, &args);

        assert_eq!(layout.arg_count, 2);
        assert_eq!(
            layout.args,
            vec![
                ComplexFormatArgLayout {
                    header_len: PRINT_COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN + 2,
                    reserved_len: 3,
                },
                ComplexFormatArgLayout {
                    header_len: PRINT_COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN,
                    reserved_len: 64,
                },
            ]
        );
    }

    #[test]
    fn complex_format_layout_shares_dynamic_budget_in_arg_layouts() {
        let context = Context::create();
        let args = vec![
            dynamic_memdump_arg(&context, 256),
            dynamic_memdump_arg(&context, 256),
        ];
        let desired_dynamic_budget = VARIABLE_READ_ERROR_PAYLOAD_LEN * args.len();
        let fixed_overhead = std::mem::size_of::<InstructionHeader>()
            + std::mem::size_of::<PrintComplexFormatData>();
        let headers_total = args
            .iter()
            .map(complex_format_arg_header_len)
            .sum::<usize>();
        let end_instruction_size =
            std::mem::size_of::<InstructionHeader>() + std::mem::size_of::<EndInstructionData>();
        let max_trace_event_size =
            end_instruction_size + fixed_overhead + headers_total + desired_dynamic_budget;

        let layout = plan_complex_format_layout(max_trace_event_size, 0, &args);

        assert_eq!(
            layout
                .args
                .iter()
                .map(|arg_layout| arg_layout.reserved_len)
                .collect::<Vec<_>>(),
            vec![
                VARIABLE_READ_ERROR_PAYLOAD_LEN,
                VARIABLE_READ_ERROR_PAYLOAD_LEN,
            ]
        );
    }

    #[test]
    fn complex_format_layout_omits_nested_values_that_do_not_fit_atomically() {
        let context = Context::create();
        let args = vec![nested_value_arg(&context, 40_000)];
        let max_trace_event_size = 32 * 1024;

        let layout = plan_complex_format_layout(max_trace_event_size, 0, &args);
        let instruction_budget = print_complex_format_instruction_budget(max_trace_event_size, 0);

        assert!(layout.total_size < instruction_budget);
        assert_eq!(layout.args[0].reserved_len, 0);
        assert!(layout.inst_data_size <= u16::MAX as usize);
    }

    #[test]
    fn complex_format_layout_reserves_nested_values_that_fit_atomically() {
        let context = Context::create();
        let args = vec![nested_value_arg(&context, 64)];

        let layout = plan_complex_format_layout(4096, 0, &args);

        assert_eq!(layout.args[0].reserved_len, 64);
    }

    #[test]
    fn short_nested_child_read_errors_stay_within_the_child_slot() {
        let llvm_ir = short_nested_child_emitter_ir();

        assert!(llvm_ir.contains("probe_read_user_memdump"));
        assert!(!llvm_ir.contains("indirect_errno_ptr_i8"));
        assert!(!llvm_ir.contains("indirect_addr_ptr_i8"));
    }

    #[test]
    fn complex_format_layout_includes_indirect_length_prefix() {
        let context = Context::create();
        let args = vec![indirect_bytes_arg(&context, 64)];

        let layout = plan_complex_format_layout(4096, 0, &args);

        assert_eq!(
            layout.args[0].reserved_len,
            ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE + 64
        );
    }

    #[test]
    fn complex_format_layout_includes_indirect_sequence_header() {
        let context = Context::create();
        let args = vec![
            indirect_sequence_arg(&context, 4, 3, 12),
            indirect_ring_sequence_arg(&context, 4, 3, 12),
        ];

        let layout = plan_complex_format_layout(4096, 0, &args);

        assert_eq!(
            layout.args[0].reserved_len,
            ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE + 12
        );
        assert_eq!(
            layout.args[1].reserved_len,
            ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE + 24
        );
        assert_eq!(
            indirect_capture_capacity(
                layout.args[1].reserved_len,
                12,
                IndirectCaptureShape::Sequence {
                    element_stride: 4,
                    max_elements: 3,
                    ring: Some(RingCaptureConfig {
                        start_offset: 8,
                        start_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                        capacity_offset: 24,
                        capacity_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                        length_kind: RingCaptureLengthKind::Explicit,
                    }),
                },
            ),
            12
        );
    }

    #[test]
    fn complex_format_layout_includes_hash_table_header_and_bucket_regions() {
        let context = Context::create();
        let args = vec![indirect_hash_table_arg(&context, 8, 7, 63)];

        let layout = plan_complex_format_layout(4096, 0, &args);

        assert_eq!(
            layout.args[0].reserved_len,
            ghostscope_protocol::HASH_TABLE_HEADER_SIZE + 63
        );
    }

    #[test]
    fn hash_table_emitter_uses_dwarf_metadata_and_storage_order() {
        let reverse_ir = hash_table_emitter_ir(
            HashTableCaptureConfig {
                control_offset: 0,
                control_access_size: ghostscope_dwarf::MemoryAccessSize::U32,
                length_offset: 4,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U32,
                bucket_mask_offset: 8,
                bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize::U32,
                entry_stride: 8,
                occupancy: ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear,
                buckets: HashTableBucketSource::ReverseFromControl,
                bucket_order: ghostscope_dwarf::HashTableBucketOrder::Reverse,
                max_buckets: 4,
            },
            36,
        );
        assert!(reverse_ir.contains("probe_read_user_hash_table_controls"));
        assert!(reverse_ir.contains("probe_read_user_hash_table_buckets"));
        assert!(reverse_ir.contains("hash_table_reverse_bucket_source"));
        assert!(reverse_ir.contains("hash_table_captured_buckets_header"));
        assert!(reverse_ir.contains("hash_table_metadata_error_payload"));
        assert!(reverse_ir.contains("hash_table_control_length_exceeds_limit"));
        assert!(reverse_ir.contains("hash_table_control_length_bounded"));
        assert!(reverse_ir.contains("hash_table_bucket_length_exceeds_limit"));
        assert!(reverse_ir.contains("hash_table_bucket_length_bounded"));

        let forward_ir = hash_table_emitter_ir(
            HashTableCaptureConfig {
                control_offset: 0,
                control_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                length_offset: 16,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                bucket_mask_offset: 24,
                bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                entry_stride: 4,
                occupancy: ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear,
                buckets: HashTableBucketSource::Forward {
                    data_offset: 8,
                    data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                },
                bucket_order: ghostscope_dwarf::HashTableBucketOrder::Forward,
                max_buckets: 4,
            },
            20,
        );
        assert!(forward_ir.contains("hash_table_data_metadata"));
        assert!(!forward_ir.contains("hash_table_reverse_bucket_source"));

        let legacy_ir = hash_table_emitter_ir(
            HashTableCaptureConfig {
                control_offset: 16,
                control_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                length_offset: 8,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                bucket_mask_offset: 0,
                bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                entry_stride: 8,
                occupancy: ghostscope_dwarf::HashTableOccupancy::NonZeroWord { word_size: 8 },
                buckets: HashTableBucketSource::LegacyAfterControl {
                    entry_alignment: 4,
                    pointer_tag_mask: 1,
                },
                bucket_order: ghostscope_dwarf::HashTableBucketOrder::Forward,
                max_buckets: 4,
            },
            64,
        );
        assert!(legacy_ir.contains("hash_table_legacy_control_address"));
        assert!(legacy_ir.contains("hash_table_legacy_hash_words_aligned_length"));
        assert!(legacy_ir.contains("hash_table_legacy_bucket_source"));
        assert!(!legacy_ir.contains("hash_table_data_metadata"));
    }

    #[test]
    fn nested_hash_table_emitter_uses_each_dwarf_storage_layout() {
        let reverse_ir = nested_hash_table_emitter_ir(
            HashTableBucketSource::ReverseFromControl,
            ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear,
        );
        assert!(
            reverse_ir.contains("%nested_hash_table_0_entry_address = sub i64"),
            "{reverse_ir}"
        );
        assert!(
            reverse_ir.contains("nested_hash_table_0_field_0_address"),
            "{reverse_ir}"
        );

        let forward_ir = nested_hash_table_emitter_ir(
            HashTableBucketSource::Forward {
                data_offset: 8,
                data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            },
            ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear,
        );
        assert!(forward_ir.contains("%nested_hash_table_0_entry_address = add i64"));
        assert!(!forward_ir.contains("nested_hash_table_legacy_bucket_base"));
        assert!(forward_ir.contains("nested_hash_table_0_field_0_address"));

        let legacy_ir = nested_hash_table_emitter_ir(
            HashTableBucketSource::LegacyAfterControl {
                entry_alignment: 4,
                pointer_tag_mask: 1,
            },
            ghostscope_dwarf::HashTableOccupancy::NonZeroWord { word_size: 8 },
        );
        assert!(legacy_ir.contains("nested_hash_table_legacy_control"));
        assert!(legacy_ir.contains("nested_hash_table_legacy_aligned_len"));
        assert!(legacy_ir.contains("nested_hash_table_legacy_bucket_base"));
        assert!(legacy_ir.contains("%nested_hash_table_0_entry_address = add i64"));
    }

    #[test]
    fn btree_emitter_uses_dwarf_node_layout_without_runtime_loops() {
        let record_size = ghostscope_protocol::BTREE_NODE_HEADER_SIZE + 2 * (4 + 2);
        let llvm_ir = btree_emitter_ir(
            BTreeCaptureConfig {
                root_pointer_offset: 0,
                root_pointer_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                root_height_offset: 8,
                root_height_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                length_offset: 16,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                node_length_offset: 54,
                node_length_access_size: ghostscope_dwarf::MemoryAccessSize::U16,
                keys: BTreeArraySource {
                    offset: 8,
                    slot_stride: 4,
                },
                values: Some(BTreeArraySource {
                    offset: 52,
                    slot_stride: 2,
                }),
                edges: BTreeEdgesSource {
                    offset_from_leaf: 56,
                    slot_stride: 8,
                    pointer_offset: 0,
                    pointer_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                    edge_count: 3,
                },
                node_capacity: 2,
                max_nodes: 3,
            },
            record_size * 3,
        );

        assert!(llvm_ir.contains("btree_length_metadata"));
        assert!(llvm_ir.contains("btree_root_pointer_metadata"));
        assert!(llvm_ir.contains("btree_node_0_length"));
        assert!(llvm_ir.contains("btree_node_0_keys_length_verifier_masked"));
        assert!(llvm_ir.contains("btree_node_0_values_length_verifier_masked"));
        assert!(llvm_ir.contains("probe_read_user_btree_node_0_keys"));
        assert!(llvm_ir.contains("probe_read_user_btree_node_0_values"));
        assert!(llvm_ir.contains("btree_node_0_edge_0"));
        assert!(llvm_ir.contains("btree_frontier_truncated"));
        assert!(llvm_ir.contains("btree_invalid"));
        assert!(!llvm_ir.contains("btree_node_loop"));
    }

    #[test]
    fn indirect_bytes_capture_respects_caps_below_error_headroom() {
        let context = Context::create();

        for max_len in 0..=3 {
            let args = vec![indirect_bytes_arg(&context, max_len)];
            let layout = plan_complex_format_layout(4096, 0, &args);
            let reserved_len = layout.args[0].reserved_len;

            assert_eq!(
                reserved_len,
                ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE + max_len
            );
            assert_eq!(
                indirect_capture_capacity(reserved_len, max_len, IndirectCaptureShape::Bytes),
                max_len
            );
        }
    }

    #[test]
    fn indirect_bytes_emitter_writes_standard_read_error_payload() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 8,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            excluded_tail_bytes: 0,
            max_len: 4,
            shape: IndirectCaptureShape::Bytes,
        });

        assert!(llvm_ir.contains("indirect_metadata_error_payload"));
        assert!(llvm_ir.contains("indirect_errno_ptr_i8"));
        assert!(llvm_ir.contains("indirect_addr_ptr_i8"));
    }

    #[test]
    fn projected_view_emitter_stops_after_each_failed_read() {
        let llvm_ir = projected_view_emitter_ir();

        assert!(llvm_ir.contains("projected_view_0_1_pointer_error"));
        assert!(llvm_ir.contains("projected_view_1_1_pointer_error"));
        assert!(llvm_ir.contains("projected_view_0_read_ok"));
        assert_eq!(
            llvm_ir
                .lines()
                .filter(|line| {
                    line.contains("call i64") && line.contains("%probe_read_user_memdump")
                })
                .count(),
            1
        );
        assert!(llvm_ir.lines().any(|line| {
            line.contains("store i64") && line.contains("%projected_view_1_output")
        }));
        assert!(!llvm_ir.contains("projected_view_1_read_ok"));
        assert!(llvm_ir.contains("projected_view_finish"));
        assert!(llvm_ir.contains("indirect_errno_ptr_i8"));
        assert!(llvm_ir.contains("indirect_addr_ptr_i8"));
    }

    #[test]
    fn indirect_bytes_emitter_uses_dwarf_metadata_widths() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U32,
            length_offset: 4,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U32,
            excluded_tail_bytes: 0,
            max_len: 4,
            shape: IndirectCaptureShape::Bytes,
        });
        let metadata_loads = llvm_ir
            .lines()
            .filter(|line| {
                let is_metadata = line.contains("loaded_value");
                let is_i32_load = line.contains("load i32");
                is_metadata && is_i32_load
            })
            .count();
        let metadata_extensions = llvm_ir
            .lines()
            .filter(|line| {
                let is_metadata = line.contains("extended");
                let is_i32_extension = line.contains("zext i32");
                is_metadata && is_i32_extension
            })
            .count();

        assert_eq!(metadata_loads, 2, "{llvm_ir}");
        assert_eq!(metadata_extensions, 2, "{llvm_ir}");
    }

    #[test]
    fn nul_terminated_bytes_emitter_excludes_the_trailing_nul() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 8,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            excluded_tail_bytes: 1,
            max_len: 16,
            shape: IndirectCaptureShape::Bytes,
        });

        assert!(llvm_ir.contains("indirect_has_excluded_tail"));
        assert!(llvm_ir.contains("indirect_adjusted_length"));
        assert!(llvm_ir.contains("indirect_logical_length"));
    }

    #[test]
    fn indirect_sequence_emitter_records_count_and_scales_by_dwarf_stride() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 8,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            excluded_tail_bytes: 0,
            max_len: 8,
            shape: IndirectCaptureShape::Sequence {
                element_stride: 4,
                max_elements: 2,
                ring: None,
            },
        });

        assert!(llvm_ir.contains("indirect_captured_count_ptr_i8_nonempty"));
        assert!(llvm_ir.contains("indirect_read_len_bytes"));
        assert!(llvm_ir.contains("indirect_read_len_exceeds_limit"));
        assert!(llvm_ir.contains("indirect_read_len_verifier_masked"));
        assert!(llvm_ir.contains("indirect_read_len_masked_exceeds_limit"));
        assert!(llvm_ir.contains("indirect_read_len_bounded"));
        assert!(llvm_ir.contains("mul i64"));
    }

    #[test]
    fn probe_read_length_keeps_a_verifier_visible_bound_after_optimization() {
        let assembly = clamped_probe_read_assembly(64);
        let mask = assembly.find("&= 127").expect("verifier mask in assembly");
        let exact_bound = assembly[mask..]
            .find("> 64")
            .map(|offset| mask + offset)
            .expect("exact upper-bound comparison in assembly");
        let probe_read = assembly[exact_bound..]
            .find("call 112")
            .map(|offset| exact_bound + offset)
            .expect("probe read helper in assembly");

        assert!(mask < exact_bound && exact_bound < probe_read, "{assembly}");
    }

    #[test]
    fn zero_sized_sequence_emitter_does_not_read_element_memory() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 8,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            excluded_tail_bytes: 0,
            max_len: 0,
            shape: IndirectCaptureShape::Sequence {
                element_stride: 0,
                max_elements: 4,
                ring: None,
            },
        });

        assert!(llvm_ir.contains("indirect_no_read_complete"));
        assert!(!llvm_ir.contains("probe_read_user_indirect"));
    }

    #[test]
    fn ring_sequence_emitter_reads_two_segments_in_logical_order() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 16,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            excluded_tail_bytes: 0,
            max_len: 16,
            shape: IndirectCaptureShape::Sequence {
                element_stride: 4,
                max_elements: 4,
                ring: Some(RingCaptureConfig {
                    start_offset: 8,
                    start_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                    capacity_offset: 24,
                    capacity_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                    length_kind: RingCaptureLengthKind::Explicit,
                }),
            },
        });

        assert!(llvm_ir.contains("indirect_ring_metadata_valid"));
        assert!(llvm_ir.contains("indirect_ring_first_address"));
        assert!(llvm_ir.contains("indirect_ring_second_payload"));
        assert!(llvm_ir.contains("indirect_ring_first_payload_len = zext i32"));
        assert!(llvm_ir.contains("indirect_ring_first_len_exceeds_limit"));
        assert!(llvm_ir.contains("indirect_ring_first_len_bounded"));
        assert!(llvm_ir.contains("indirect_ring_second_len_i32_exceeds_limit"));
        assert!(llvm_ir.contains("indirect_ring_second_len_i32_bounded"));
        assert!(llvm_ir.contains("probe_read_user_indirect_ring_first"));
        assert!(llvm_ir.contains("probe_read_user_indirect_ring_second"));
    }

    #[test]
    fn legacy_ring_sequence_emitter_derives_wrapped_distance() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 16,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            excluded_tail_bytes: 0,
            max_len: 16,
            shape: IndirectCaptureShape::Sequence {
                element_stride: 4,
                max_elements: 4,
                ring: Some(RingCaptureConfig {
                    start_offset: 8,
                    start_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                    capacity_offset: 24,
                    capacity_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                    length_kind: RingCaptureLengthKind::End,
                }),
            },
        });

        assert!(llvm_ir.contains("indirect_ring_direct_distance"));
        assert!(llvm_ir.contains("indirect_ring_wrapped_distance"));
        assert!(llvm_ir.contains("indirect_ring_distance"));
    }
}

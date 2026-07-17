use super::*;

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
    max_len: usize,
    shape: IndirectCaptureShape,
}

#[derive(Clone, Copy)]
struct HashTableCaptureConfig {
    control_offset: u64,
    control_access_size: ghostscope_dwarf::MemoryAccessSize,
    data: Option<(u64, ghostscope_dwarf::MemoryAccessSize)>,
    length_offset: u64,
    length_access_size: ghostscope_dwarf::MemoryAccessSize,
    bucket_mask_offset: u64,
    bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize,
    entry_stride: u64,
    bucket_order: ghostscope_dwarf::HashTableBucketOrder,
    max_buckets: usize,
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
        ComplexArgSource::MemDumpDynamic { .. } => None,
        ComplexArgSource::IndirectBytes { .. } => None,
        ComplexArgSource::IndirectSequence { .. } => None,
        ComplexArgSource::IndirectRingSequence { .. } => None,
        ComplexArgSource::IndirectHashTable { .. } => None,
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
        }

        arg_payload_plans.push((header_len, static_payload_len));
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
        .map(|(header_len, static_payload_len)| {
            let reserved_len =
                static_payload_len.unwrap_or_else(|| dynamic_reservations_iter.next().unwrap_or(0));
            ComplexFormatArgLayout {
                header_len,
                reserved_len,
            }
        })
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
        let mut complex_args: Vec<ComplexArg<'ctx>> = Vec::with_capacity(args.len());

        // Parse placeholders from the format string to support extended specifiers
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Conv {
            Default,
            HexLower,
            HexUpper,
            Ptr,
            Ascii,
        }
        #[derive(Clone, Debug, PartialEq)]
        enum LenSpec {
            None,
            Static(usize),
            Star,
            Capture(String),
        }

        fn parse_static_len(spec: &str) -> Option<usize> {
            if spec.chars().all(|c| c.is_ascii_digit()) {
                return spec.parse::<usize>().ok();
            }
            if let Some(hex) = spec.strip_prefix("0x") {
                if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return usize::from_str_radix(hex, 16).ok();
                }
            }
            if let Some(oct) = spec.strip_prefix("0o") {
                if !oct.is_empty() && oct.chars().all(|c| matches!(c, '0'..='7')) {
                    return usize::from_str_radix(oct, 8).ok();
                }
            }
            if let Some(bin) = spec.strip_prefix("0b") {
                if !bin.is_empty() && bin.chars().all(|c| matches!(c, '0' | '1')) {
                    return usize::from_str_radix(bin, 2).ok();
                }
            }
            None
        }

        fn parse_slots(fmt: &str) -> Vec<(Conv, LenSpec)> {
            let mut res = Vec::new();
            let mut it = fmt.chars().peekable();
            while let Some(ch) = it.next() {
                if ch == '{' {
                    if it.peek() == Some(&'{') {
                        it.next();
                        continue;
                    }
                    let mut content = String::new();
                    for c in it.by_ref() {
                        if c == '}' {
                            break;
                        }
                        content.push(c);
                    }
                    if content.is_empty() {
                        res.push((Conv::Default, LenSpec::None));
                    } else if let Some(rest) = content.strip_prefix(':') {
                        let mut sit = rest.chars();
                        let conv = match sit.next().unwrap_or(' ') {
                            'x' => Conv::HexLower,
                            'X' => Conv::HexUpper,
                            'p' => Conv::Ptr,
                            's' => Conv::Ascii,
                            _ => Conv::Default,
                        };
                        let rest: String = sit.collect();
                        let lens = if rest.is_empty() {
                            LenSpec::None
                        } else if let Some(r) = rest.strip_prefix('.') {
                            if r == "*" {
                                LenSpec::Star
                            } else if let Some(s) = r.strip_suffix('$') {
                                LenSpec::Capture(s.to_string())
                            } else if let Some(n) = parse_static_len(r) {
                                LenSpec::Static(n)
                            } else {
                                LenSpec::None
                            }
                        } else {
                            LenSpec::None
                        };
                        res.push((conv, lens));
                    } else {
                        res.push((Conv::Default, LenSpec::None));
                    }
                }
            }
            res
        }

        let slots = parse_slots(format);
        let mut ai = 0usize; // arg cursor
        for (conv, lens) in slots.into_iter() {
            match conv {
                Conv::Default => {
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
                Conv::Ptr => {
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
                Conv::HexLower | Conv::HexUpper | Conv::Ascii => {
                    // Memory dump; handle static length at compile time. Other cases use default read and let user space trim.
                    // Handle star: consume length arg (as computed int) then value arg
                    let wants_ascii = matches!(conv, Conv::Ascii);
                    match lens {
                        LenSpec::Static(n) if ai < args.len() => {
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
                        LenSpec::Star => {
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
                        LenSpec::Capture(name) => {
                            // Use script variable `name` as length; emit a length argument + a dynamic mem-dump argument
                            if ai >= args.len() {
                                break;
                            }
                            if !self.variable_exists(&name) {
                                return Err(CodeGenError::TypeError(format!(
                                    "capture length variable '{name}' not found"
                                )));
                            }
                            // length as computed int
                            let len_val = self.load_variable(&name)?;
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
                    let _ = wants_ascii; // reserved for future per-arg metadata
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
    ) -> Result<()> {
        self.emit_complex_format_memdump_at(status_ptr, var_data_ptr, var_data_ptr, address, len)
    }

    fn emit_complex_format_memdump_at(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        payload_ptr: PointerValue<'ctx>,
        dst_ptr: PointerValue<'ctx>,
        address: &RuntimeAddress<'ctx>,
        len: usize,
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
        // SAFETY: payload_ptr points at the read-error payload.
        let errno_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    payload_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET as u64, false)],
                    "errno_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        let errno_ptr = self
            .builder
            .build_pointer_cast(
                errno_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "errno_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let errno = self.build_errno_i32(ret, "errno_i32")?;
        self.builder
            .build_store(errno_ptr, errno)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // SAFETY: read-error payload reserves enough bytes for the addr field.
        let addr_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    payload_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET as u64, false)],
                    "addr_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        let addr_ptr = self
            .builder
            .build_pointer_cast(
                addr_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "addr_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(addr_ptr, address.value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
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
                self.emit_complex_format_memdump_at(
                    status_ptr,
                    var_data_ptr,
                    field_ptr,
                    &address,
                    field.value_len,
                )?;
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

    fn emit_complex_format_indirect(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        reserved_len: usize,
        capture: IndirectCaptureConfig,
    ) -> Result<()> {
        let prefix_len = capture.shape.prefix_len();
        if reserved_len < prefix_len {
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_fail()?;
            return Ok(());
        }

        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let ring_config = match capture.shape {
            IndirectCaptureShape::Sequence { ring, .. } => ring,
            IndirectCaptureShape::Bytes => None,
        };
        let data_member = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(capture.data_offset, false),
                "indirect_data_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let length_member = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(capture.length_offset, false),
                "indirect_length_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let data_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(data_member),
            capture.data_access_size,
            Some(status_ptr),
            "indirect_data_metadata",
        )?;
        let data_address = data_read.value.into_int_value();
        let length_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(length_member),
            capture.length_access_size,
            Some(status_ptr),
            "indirect_length_metadata",
        )?;
        let length_value = length_read.value.into_int_value();
        let ring_reads = if let Some(ring) = ring_config {
            let start_member = self
                .builder
                .build_int_add(
                    descriptor.value,
                    i64_type.const_int(ring.start_offset, false),
                    "indirect_ring_start_member",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let start_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(start_member),
                ring.start_access_size,
                Some(status_ptr),
                "indirect_ring_start_metadata",
            )?;
            let capacity_member = self
                .builder
                .build_int_add(
                    descriptor.value,
                    i64_type.const_int(ring.capacity_offset, false),
                    "indirect_ring_capacity_member",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let capacity_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(capacity_member),
                ring.capacity_access_size,
                Some(status_ptr),
                "indirect_ring_capacity_metadata",
            )?;
            Some((
                ring,
                start_member,
                start_read,
                capacity_member,
                capacity_read,
            ))
        } else {
            None
        };

        let mut original_len = length_value;
        let mut ring_start = None;
        let mut ring_capacity = None;
        let mut ring_metadata_valid = None;
        if let Some((ring, _, start_read, _, capacity_read)) = &ring_reads {
            let start = start_read.value.into_int_value();
            let capacity = capacity_read.value.into_int_value();
            if matches!(ring.length_kind, RingCaptureLengthKind::End) {
                let direct_distance = self
                    .builder
                    .build_int_sub(length_value, start, "indirect_ring_direct_distance")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let wrapped_prefix = self
                    .builder
                    .build_int_sub(capacity, start, "indirect_ring_wrapped_prefix")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let wrapped_distance = self
                    .builder
                    .build_int_add(
                        wrapped_prefix,
                        length_value,
                        "indirect_ring_wrapped_distance",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let no_wrap = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::UGE,
                        length_value,
                        start,
                        "indirect_ring_no_wrap",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                original_len = self
                    .builder
                    .build_select(
                        no_wrap,
                        direct_distance,
                        wrapped_distance,
                        "indirect_ring_distance",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
            }

            let capacity_nonzero = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    capacity,
                    i64_type.const_zero(),
                    "indirect_ring_capacity_nonzero",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let start_in_bounds = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    start,
                    capacity,
                    "indirect_ring_start_in_bounds",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let length_valid = match ring.length_kind {
                RingCaptureLengthKind::Explicit => self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::ULE,
                        original_len,
                        capacity,
                        "indirect_ring_length_in_bounds",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
                RingCaptureLengthKind::End => self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::ULT,
                        length_value,
                        capacity,
                        "indirect_ring_end_in_bounds",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
            };
            let indices_valid = self
                .builder
                .build_and(
                    capacity_nonzero,
                    start_in_bounds,
                    "indirect_ring_indices_valid",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            ring_metadata_valid = Some(
                self.builder
                    .build_and(indices_valid, length_valid, "indirect_ring_metadata_valid")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
            );
            ring_start = Some(start);
            ring_capacity = Some(capacity);
        }

        let current_status = self
            .builder
            .build_load(
                self.context.i8_type(),
                status_ptr,
                "indirect_metadata_status",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let metadata_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                self.context.i8_type().const_zero(),
                "indirect_metadata_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let function = self.current_function("compile indirect value capture")?;
        let metadata_ok_block = self
            .context
            .append_basic_block(function, "indirect_metadata_ok");
        let metadata_error_block = self
            .context
            .append_basic_block(function, "indirect_metadata_error");
        let continue_block = self
            .context
            .append_basic_block(function, "indirect_continue");
        self.builder
            .build_conditional_branch(metadata_ok, metadata_ok_block, metadata_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_error_block);
        let metadata_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
                "indirect_metadata_read_error",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let metadata_payload_block = self
            .context
            .append_basic_block(function, "indirect_metadata_error_payload");
        self.builder
            .build_conditional_branch(metadata_read_error, metadata_payload_block, continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_payload_block);
        let (mut metadata_helper_result, mut metadata_error_address) = ring_reads
            .as_ref()
            .map(|(_, _, _, capacity_member, capacity_read)| {
                (capacity_read.helper_result, *capacity_member)
            })
            .unwrap_or((length_read.helper_result, length_member));
        if let Some((_, start_member, start_read, _, _)) = &ring_reads {
            (metadata_helper_result, metadata_error_address) = self
                .select_indirect_metadata_failure(
                    start_read,
                    *start_member,
                    metadata_helper_result,
                    metadata_error_address,
                    "indirect_ring_start",
                )?;
        }
        (metadata_helper_result, metadata_error_address) = self.select_indirect_metadata_failure(
            &length_read,
            length_member,
            metadata_helper_result,
            metadata_error_address,
            "indirect_length",
        )?;
        (metadata_helper_result, metadata_error_address) = self.select_indirect_metadata_failure(
            &data_read,
            data_member,
            metadata_helper_result,
            metadata_error_address,
            "indirect_data",
        )?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            metadata_helper_result,
            metadata_error_address,
        )?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_ok_block);
        let length_prefix_ptr = self
            .builder
            .build_pointer_cast(var_data_ptr, ptr_type, "indirect_length_prefix")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder
            .build_store(length_prefix_ptr, original_len)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        if matches!(capture.shape, IndirectCaptureShape::Sequence { .. }) {
            // SAFETY: sequence payloads reserve the complete two-u64 header.
            let captured_count_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[i32_type.const_int(
                            ghostscope_protocol::INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET as u64,
                            false,
                        )],
                        "indirect_captured_count_ptr_i8",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let captured_count_ptr = self
                .builder
                .build_pointer_cast(
                    captured_count_ptr_i8,
                    ptr_type,
                    "indirect_captured_count_ptr",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_store(captured_count_ptr, i64_type.const_zero())
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        let is_empty = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                original_len,
                i64_type.const_zero(),
                "indirect_is_empty",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let empty_block = self.context.append_basic_block(function, "indirect_empty");
        let nonempty_block = self
            .context
            .append_basic_block(function, "indirect_nonempty");
        self.builder
            .build_conditional_branch(is_empty, empty_block, nonempty_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(empty_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ZeroLength as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(nonempty_block);
        if let Some(metadata_valid) = ring_metadata_valid {
            let ring_valid_block = self
                .context
                .append_basic_block(function, "indirect_ring_valid");
            let ring_invalid_block = self
                .context
                .append_basic_block(function, "indirect_ring_invalid");
            self.builder
                .build_conditional_branch(metadata_valid, ring_valid_block, ring_invalid_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(ring_invalid_block);
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::AccessError as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(ring_valid_block);
        }
        let capture_capacity =
            indirect_capture_capacity(reserved_len, capture.max_len, capture.shape);
        let (unit_size, max_units) = match capture.shape {
            IndirectCaptureShape::Bytes => (1usize, capture_capacity),
            IndirectCaptureShape::Sequence {
                element_stride,
                max_elements,
                ..
            } => {
                let stride = usize::try_from(element_stride).map_err(|_| {
                    CodeGenError::DwarfError(format!(
                        "sequence element DWARF size {element_stride} does not fit this host"
                    ))
                })?;
                let payload_elements = if stride == 0 {
                    max_elements
                } else {
                    capture_capacity / stride
                };
                (stride, max_elements.min(payload_elements))
            }
        };
        let capture_limit = i64_type.const_int(max_units as u64, false);
        let is_truncated = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                original_len,
                capture_limit,
                "indirect_is_truncated",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let captured_units = self
            .builder
            .build_select(
                is_truncated,
                capture_limit,
                original_len,
                "indirect_captured_units",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();

        if matches!(capture.shape, IndirectCaptureShape::Sequence { .. }) {
            // SAFETY: sequence payloads reserve the complete two-u64 header.
            let captured_count_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[i32_type.const_int(
                            ghostscope_protocol::INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET as u64,
                            false,
                        )],
                        "indirect_captured_count_ptr_i8_nonempty",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let captured_count_ptr = self
                .builder
                .build_pointer_cast(
                    captured_count_ptr_i8,
                    ptr_type,
                    "indirect_captured_count_ptr_nonempty",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_store(captured_count_ptr, captured_units)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }

        if max_units == 0 || unit_size == 0 {
            let truncated_block = self
                .context
                .append_basic_block(function, "indirect_no_read_truncated");
            let complete_block = self
                .context
                .append_basic_block(function, "indirect_no_read_complete");
            self.builder
                .build_conditional_branch(is_truncated, truncated_block, complete_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(truncated_block);
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_success()?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(complete_block);
            self.mark_any_success()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(continue_block);
            return Ok(());
        }

        let is_null = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                data_address,
                i64_type.const_zero(),
                "indirect_data_is_null",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let null_block = self.context.append_basic_block(function, "indirect_null");
        let read_block = self.context.append_basic_block(function, "indirect_read");
        self.builder
            .build_conditional_branch(is_null, null_block, read_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(read_block);
        // SAFETY: reserved_len includes the fixed length prefix.
        let byte_payload_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    var_data_ptr,
                    &[i32_type.const_int(prefix_len as u64, false)],
                    "indirect_byte_payload",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        let destination = self
            .builder
            .build_pointer_cast(byte_payload_ptr, ptr_type, "indirect_destination")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let (read_result, read_error_address, read_ok) = if let (Some(start), Some(capacity)) =
            (ring_start, ring_capacity)
        {
            let available_before_wrap = self
                .builder
                .build_int_sub(capacity, start, "indirect_ring_available_before_wrap")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let wraps = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGT,
                    captured_units,
                    available_before_wrap,
                    "indirect_ring_wraps",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_units = self
                .builder
                .build_select(
                    wraps,
                    available_before_wrap,
                    captured_units,
                    "indirect_ring_first_units",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let stride = i64_type.const_int(unit_size as u64, false);
            let start_offset = self
                .builder
                .build_int_mul(start, stride, "indirect_ring_start_offset")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_address = self
                .builder
                .build_int_add(data_address, start_offset, "indirect_ring_first_address")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_len = self
                .builder
                .build_int_mul(first_units, stride, "indirect_ring_first_len")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_len_i32 = self
                .builder
                .build_int_truncate(first_len, i32_type, "indirect_ring_first_len_i32")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_source = self
                .builder
                .build_int_to_ptr(first_address, ptr_type, "indirect_ring_first_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            // SAFETY: first_len is bounded by the reserved sequence payload.
            let second_payload_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        byte_payload_ptr,
                        &[first_len],
                        "indirect_ring_second_payload",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let second_destination = self
                .builder
                .build_pointer_cast(
                    second_payload_ptr,
                    ptr_type,
                    "indirect_ring_second_destination",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[
                        destination.into(),
                        first_len_i32.into(),
                        first_source.into(),
                    ],
                    i64_type.into(),
                    "probe_read_user_indirect_ring_first",
                )?
                .into_int_value();

            let second_read_block = self
                .context
                .append_basic_block(function, "indirect_ring_second_read");
            let no_second_read_block = self
                .context
                .append_basic_block(function, "indirect_ring_no_second_read");
            let ring_read_complete_block = self
                .context
                .append_basic_block(function, "indirect_ring_read_complete");
            self.builder
                .build_conditional_branch(wraps, second_read_block, no_second_read_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(no_second_read_block);
            self.builder
                .build_unconditional_branch(ring_read_complete_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(second_read_block);
            let unbounded_second_units = self
                .builder
                .build_int_sub(
                    captured_units,
                    available_before_wrap,
                    "indirect_ring_unbounded_second_units",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_units_exceed_limit = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGT,
                    unbounded_second_units,
                    capture_limit,
                    "indirect_ring_second_units_exceed_limit",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_units = self
                .builder
                .build_select(
                    second_units_exceed_limit,
                    capture_limit,
                    unbounded_second_units,
                    "indirect_ring_second_units",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let second_len = self
                .builder
                .build_int_mul(second_units, stride, "indirect_ring_second_len")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_len_limit = i64_type.const_int(capture_capacity as u64, false);
            let second_len_exceeds_limit = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGT,
                    second_len,
                    second_len_limit,
                    "indirect_ring_second_len_exceeds_limit",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bounded_second_len = self
                .builder
                .build_select(
                    second_len_exceeds_limit,
                    second_len_limit,
                    second_len,
                    "indirect_ring_bounded_second_len",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let second_len_i32 = self
                .builder
                .build_int_truncate(bounded_second_len, i32_type, "indirect_ring_second_len_i32")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_source = self
                .builder
                .build_int_to_ptr(data_address, ptr_type, "indirect_ring_second_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[
                        second_destination.into(),
                        second_len_i32.into(),
                        second_source.into(),
                    ],
                    i64_type.into(),
                    "probe_read_user_indirect_ring_second",
                )?
                .into_int_value();
            self.builder
                .build_unconditional_branch(ring_read_complete_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(ring_read_complete_block);
            let second_result_phi = self
                .builder
                .build_phi(i64_type, "indirect_ring_second_result")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            second_result_phi.add_incoming(&[
                (&i64_type.const_zero(), no_second_read_block),
                (&second_result, second_read_block),
            ]);
            let second_result = second_result_phi.as_basic_value().into_int_value();
            let first_failed = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    first_result,
                    i64_type.const_zero(),
                    "indirect_ring_first_failed",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let read_result = self
                .builder
                .build_select(
                    first_failed,
                    first_result,
                    second_result,
                    "indirect_ring_read_result",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let read_error_address = self
                .builder
                .build_select(
                    first_failed,
                    first_address,
                    data_address,
                    "indirect_ring_read_error_address",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let read_ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    read_result,
                    i64_type.const_zero(),
                    "indirect_ring_read_ok",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            (read_result, read_error_address, read_ok)
        } else {
            let read_len = self
                .builder
                .build_int_mul(
                    captured_units,
                    i64_type.const_int(unit_size as u64, false),
                    "indirect_read_len_bytes",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let read_len = self
                .builder
                .build_int_truncate(read_len, i32_type, "indirect_read_len_i32")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let source = self
                .builder
                .build_int_to_ptr(data_address, ptr_type, "indirect_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let read_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[destination.into(), read_len.into(), source.into()],
                    i64_type.into(),
                    "probe_read_user_indirect",
                )?
                .into_int_value();
            let read_ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    read_result,
                    i64_type.const_zero(),
                    "indirect_read_ok",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            (read_result, data_address, read_ok)
        };
        let read_ok_block = self
            .context
            .append_basic_block(function, "indirect_read_ok");
        let read_error_block = self
            .context
            .append_basic_block(function, "indirect_read_error");
        self.builder
            .build_conditional_branch(read_ok, read_ok_block, read_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(read_error_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            read_result,
            read_error_address,
        )?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(read_ok_block);
        let truncated_block = self
            .context
            .append_basic_block(function, "indirect_truncated");
        let complete_block = self
            .context
            .append_basic_block(function, "indirect_complete");
        self.builder
            .build_conditional_branch(is_truncated, truncated_block, complete_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(truncated_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::Truncated as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_success()?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(complete_block);
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(continue_block);
        Ok(())
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

    fn emit_complex_format_hash_table(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        reserved_len: usize,
        capture: HashTableCaptureConfig,
    ) -> Result<()> {
        let header_len = ghostscope_protocol::HASH_TABLE_HEADER_SIZE;
        if reserved_len < header_len {
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_fail()?;
            return Ok(());
        }

        let stride = usize::try_from(capture.entry_stride).map_err(|_| {
            CodeGenError::DwarfError(format!(
                "hash-table entry DWARF size {} does not fit this host",
                capture.entry_stride
            ))
        })?;
        let bytes_per_bucket = stride.checked_add(1).ok_or_else(|| {
            CodeGenError::DwarfError("hash-table bucket capture size overflow".to_string())
        })?;
        let reservation_buckets = reserved_len
            .saturating_sub(header_len)
            .checked_div(bytes_per_bucket)
            .unwrap_or(0);
        let max_buckets = capture.max_buckets.min(reservation_buckets);
        let bucket_payload_offset = header_len.checked_add(max_buckets).ok_or_else(|| {
            CodeGenError::DwarfError("hash-table bucket offset overflow".to_string())
        })?;
        let max_bucket_bytes = max_buckets.checked_mul(stride).ok_or_else(|| {
            CodeGenError::DwarfError("hash-table bucket payload overflow".to_string())
        })?;
        if max_buckets > u32::MAX as usize || max_bucket_bytes > u32::MAX as usize {
            return Err(CodeGenError::DwarfError(
                "hash-table capture exceeds the eBPF helper length width".to_string(),
            ));
        }

        let i8_type = self.context.i8_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let member_address = |offset: u64, name: &str| {
            self.builder
                .build_int_add(descriptor.value, i64_type.const_int(offset, false), name)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))
        };
        let control_member = member_address(capture.control_offset, "hash_table_control_member")?;
        let length_member = member_address(capture.length_offset, "hash_table_length_member")?;
        let bucket_mask_member =
            member_address(capture.bucket_mask_offset, "hash_table_bucket_mask_member")?;
        let data_member = capture
            .data
            .map(|(offset, access_size)| {
                member_address(offset, "hash_table_data_member")
                    .map(|address| (address, access_size))
            })
            .transpose()?;
        let control_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(control_member),
            capture.control_access_size,
            Some(status_ptr),
            "hash_table_control_metadata",
        )?;
        let length_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(length_member),
            capture.length_access_size,
            Some(status_ptr),
            "hash_table_length_metadata",
        )?;
        let bucket_mask_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(bucket_mask_member),
            capture.bucket_mask_access_size,
            Some(status_ptr),
            "hash_table_bucket_mask_metadata",
        )?;
        let data_read = if let Some((address, access_size)) = data_member {
            let read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(address),
                access_size,
                Some(status_ptr),
                "hash_table_data_metadata",
            )?;
            Some((address, read))
        } else {
            None
        };

        let current_status = self
            .builder
            .build_load(i8_type, status_ptr, "hash_table_metadata_status")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let metadata_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                i8_type.const_zero(),
                "hash_table_metadata_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let function = self.current_function("compile hash-table value capture")?;
        let metadata_ok_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_ok");
        let metadata_error_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_error");
        let continue_block = self
            .context
            .append_basic_block(function, "hash_table_continue");
        self.builder
            .build_conditional_branch(metadata_ok, metadata_ok_block, metadata_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_error_block);
        let metadata_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                i8_type.const_int(VariableStatus::ReadError as u64, false),
                "hash_table_metadata_read_error",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let metadata_payload_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_error_payload");
        self.builder
            .build_conditional_branch(metadata_read_error, metadata_payload_block, continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_payload_block);
        let (mut helper_result, mut error_address) =
            (bucket_mask_read.helper_result, bucket_mask_member);
        if let Some((data_member, data_read)) = &data_read {
            (helper_result, error_address) = self.select_indirect_metadata_failure(
                data_read,
                *data_member,
                helper_result,
                error_address,
                "hash_table_data",
            )?;
        }
        (helper_result, error_address) = self.select_indirect_metadata_failure(
            &bucket_mask_read,
            bucket_mask_member,
            helper_result,
            error_address,
            "hash_table_bucket_mask",
        )?;
        (helper_result, error_address) = self.select_indirect_metadata_failure(
            &length_read,
            length_member,
            helper_result,
            error_address,
            "hash_table_length",
        )?;
        (helper_result, error_address) = self.select_indirect_metadata_failure(
            &control_read,
            control_member,
            helper_result,
            error_address,
            "hash_table_control",
        )?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            helper_result,
            error_address,
        )?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_ok_block);
        let control_address = control_read.value.into_int_value();
        let original_count = length_read.value.into_int_value();
        let bucket_mask = bucket_mask_read.value.into_int_value();
        let capacity = self
            .builder
            .build_int_add(
                bucket_mask,
                i64_type.const_int(1, false),
                "hash_table_capacity",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let capacity_nonzero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                capacity,
                i64_type.const_zero(),
                "hash_table_capacity_nonzero",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let length_valid = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                original_count,
                capacity,
                "hash_table_length_valid",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let metadata_valid = self
            .builder
            .build_and(capacity_nonzero, length_valid, "hash_table_metadata_valid")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let valid_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_valid");
        let invalid_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_invalid");
        self.builder
            .build_conditional_branch(metadata_valid, valid_block, invalid_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(invalid_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::AccessError as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(valid_block);
        self.store_complex_payload_u64(var_data_ptr, 0, original_count, "hash_table_item_count")?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_CAPACITY_OFFSET,
            capacity,
            "hash_table_capacity_header",
        )?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_CAPTURED_BUCKETS_OFFSET,
            i64_type.const_zero(),
            "hash_table_captured_buckets_empty",
        )?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_BUCKET_DATA_OFFSET,
            i64_type.const_int(bucket_payload_offset as u64, false),
            "hash_table_bucket_payload_offset",
        )?;
        let is_empty = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                original_count,
                i64_type.const_zero(),
                "hash_table_is_empty",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let empty_block = self
            .context
            .append_basic_block(function, "hash_table_empty");
        let nonempty_block = self
            .context
            .append_basic_block(function, "hash_table_nonempty");
        self.builder
            .build_conditional_branch(is_empty, empty_block, nonempty_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(empty_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::ZeroLength as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(nonempty_block);
        if max_buckets == 0 {
            self.builder
                .build_store(
                    status_ptr,
                    i8_type.const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_success()?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder.position_at_end(continue_block);
            return Ok(());
        }

        let capture_limit = i64_type.const_int(max_buckets as u64, false);
        let capacity_exceeds_limit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                capacity,
                capture_limit,
                "hash_table_capacity_exceeds_limit",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let captured_buckets = self
            .builder
            .build_select(
                capacity_exceeds_limit,
                capture_limit,
                capacity,
                "hash_table_captured_buckets",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_CAPTURED_BUCKETS_OFFSET,
            captured_buckets,
            "hash_table_captured_buckets_header",
        )?;

        let data_address = data_read
            .as_ref()
            .map(|(_, read)| read.value.into_int_value());
        let control_null = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                control_address,
                i64_type.const_zero(),
                "hash_table_control_null",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let pointer_null = if stride > 0 {
            if let Some(data_address) = data_address {
                let data_null = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        data_address,
                        i64_type.const_zero(),
                        "hash_table_data_null",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder
                    .build_or(control_null, data_null, "hash_table_pointer_null")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            } else {
                control_null
            }
        } else {
            control_null
        };
        let null_block = self
            .context
            .append_basic_block(function, "hash_table_null_pointer");
        let control_read_block = self
            .context
            .append_basic_block(function, "hash_table_read_controls");
        self.builder
            .build_conditional_branch(pointer_null, null_block, control_read_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(control_read_block);
        // SAFETY: the hash-table header and max_buckets control bytes are
        // included in the reservation validated above.
        let control_destination_i8 = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    var_data_ptr,
                    &[i32_type.const_int(header_len as u64, false)],
                    "hash_table_control_destination_i8",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        let control_destination = self
            .builder
            .build_pointer_cast(
                control_destination_i8,
                ptr_type,
                "hash_table_control_destination",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_length = self
            .builder
            .build_int_truncate(captured_buckets, i32_type, "hash_table_control_length")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_source = self
            .builder
            .build_int_to_ptr(control_address, ptr_type, "hash_table_control_source")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_result = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[
                    control_destination.into(),
                    control_length.into(),
                    control_source.into(),
                ],
                i64_type.into(),
                "probe_read_user_hash_table_controls",
            )?
            .into_int_value();
        let control_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                control_result,
                i64_type.const_zero(),
                "hash_table_control_read_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_ok_block = self
            .context
            .append_basic_block(function, "hash_table_control_read_ok");
        let control_error_block = self
            .context
            .append_basic_block(function, "hash_table_control_read_error");
        self.builder
            .build_conditional_branch(control_ok, control_ok_block, control_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(control_error_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            control_result,
            control_address,
        )?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(control_ok_block);
        let finish_read_block = if stride == 0 {
            control_ok_block
        } else {
            // SAFETY: bucket_payload_offset and max_bucket_bytes were derived
            // from the same reservation, so this fixed destination is in bounds.
            let bucket_destination_i8 = unsafe {
                self.builder
                    .build_gep(
                        i8_type,
                        var_data_ptr,
                        &[i32_type.const_int(bucket_payload_offset as u64, false)],
                        "hash_table_bucket_destination_i8",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let bucket_destination = self
                .builder
                .build_pointer_cast(
                    bucket_destination_i8,
                    ptr_type,
                    "hash_table_bucket_destination",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_length_i64 = self
                .builder
                .build_int_mul(
                    captured_buckets,
                    i64_type.const_int(stride as u64, false),
                    "hash_table_bucket_length_i64",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_length = self
                .builder
                .build_int_truncate(bucket_length_i64, i32_type, "hash_table_bucket_length")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_source_address = match capture.bucket_order {
                ghostscope_dwarf::HashTableBucketOrder::Forward => {
                    data_address.ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "forward hash-table capture is missing a data pointer".to_string(),
                        )
                    })?
                }
                ghostscope_dwarf::HashTableBucketOrder::Reverse => self
                    .builder
                    .build_int_sub(
                        control_address,
                        bucket_length_i64,
                        "hash_table_reverse_bucket_source",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
            };
            let bucket_source = self
                .builder
                .build_int_to_ptr(bucket_source_address, ptr_type, "hash_table_bucket_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[
                        bucket_destination.into(),
                        bucket_length.into(),
                        bucket_source.into(),
                    ],
                    i64_type.into(),
                    "probe_read_user_hash_table_buckets",
                )?
                .into_int_value();
            let bucket_ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    bucket_result,
                    i64_type.const_zero(),
                    "hash_table_bucket_read_ok",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_ok_block = self
                .context
                .append_basic_block(function, "hash_table_bucket_read_ok");
            let bucket_error_block = self
                .context
                .append_basic_block(function, "hash_table_bucket_read_error");
            self.builder
                .build_conditional_branch(bucket_ok, bucket_ok_block, bucket_error_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(bucket_error_block);
            self.builder
                .build_store(
                    status_ptr,
                    i8_type.const_int(VariableStatus::ReadError as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.emit_complex_format_read_error_payload(
                var_data_ptr,
                reserved_len,
                bucket_result,
                bucket_source_address,
            )?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            bucket_ok_block
        };

        self.builder.position_at_end(finish_read_block);
        let truncated_block = self
            .context
            .append_basic_block(function, "hash_table_truncated");
        let complete_block = self
            .context
            .append_basic_block(function, "hash_table_complete");
        self.builder
            .build_conditional_branch(capacity_exceeds_limit, truncated_block, complete_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(truncated_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::Truncated as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_success()?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(complete_block);
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(continue_block);
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
            ComplexArgSource::MemDump { address, len } => {
                self.emit_complex_format_memdump(status_ptr, var_data_ptr, address, *len)
            }
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
                data,
                length_offset,
                length_access_size,
                bucket_mask_offset,
                bucket_mask_access_size,
                entry_stride,
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
                    data: *data,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    bucket_mask_offset: *bucket_mask_offset,
                    bucket_mask_access_size: *bucket_mask_access_size,
                    entry_stride: *entry_stride,
                    bucket_order: *bucket_order,
                    max_buckets: *max_buckets,
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
                data: None,
                length_offset: 8,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                bucket_mask_offset: 16,
                bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                entry_stride,
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
                data: None,
                length_offset: 4,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U32,
                bucket_mask_offset: 8,
                bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize::U32,
                entry_stride: 8,
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

        let forward_ir = hash_table_emitter_ir(
            HashTableCaptureConfig {
                control_offset: 0,
                control_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                data: Some((8, ghostscope_dwarf::MemoryAccessSize::U64)),
                length_offset: 16,
                length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                bucket_mask_offset: 24,
                bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
                entry_stride: 4,
                bucket_order: ghostscope_dwarf::HashTableBucketOrder::Forward,
                max_buckets: 4,
            },
            20,
        );
        assert!(forward_ir.contains("hash_table_data_metadata"));
        assert!(!forward_ir.contains("hash_table_reverse_bucket_source"));
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
    fn indirect_sequence_emitter_records_count_and_scales_by_dwarf_stride() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 8,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            max_len: 8,
            shape: IndirectCaptureShape::Sequence {
                element_stride: 4,
                max_elements: 2,
                ring: None,
            },
        });

        assert!(llvm_ir.contains("indirect_captured_count_ptr_i8_nonempty"));
        assert!(llvm_ir.contains("indirect_read_len_bytes"));
        assert!(llvm_ir.contains("mul i64"));
    }

    #[test]
    fn zero_sized_sequence_emitter_does_not_read_element_memory() {
        let llvm_ir = indirect_emitter_ir(IndirectCaptureConfig {
            data_offset: 0,
            data_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
            length_offset: 8,
            length_access_size: ghostscope_dwarf::MemoryAccessSize::U64,
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

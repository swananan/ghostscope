use super::*;

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
        let format_string_index = self.trace_context.add_string(format.to_string());
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
                            .add_variable_name(self.expr_to_name(expr)),
                        type_index: self.add_synthesized_type_index_for_kind(TypeKind::Pointer),
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
                                    .add_variable_name(self.expr_to_name(expr)),
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
                                }),
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
                                    .add_variable_name("__len".into()),
                                type_index: self.add_synthesized_type_index_for_kind(TypeKind::U64),
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
                                    .add_variable_name(self.expr_to_name(val_expr)),
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
                                }),
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
                                var_name_index: self.trace_context.add_variable_name(name.clone()),
                                type_index: self.add_synthesized_type_index_for_kind(TypeKind::U64),
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
                                    .add_variable_name(self.expr_to_name(val_expr)),
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
                                }),
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
    /// Generate eBPF code for PrintComplexFormat instruction with runtime reads for variables
    pub(super) fn generate_print_complex_format_instruction(
        &mut self,
        format_string_index: u16,
        complex_args: &[ComplexArg<'ctx>],
    ) -> Result<()> {
        use InstructionType::PrintComplexFormat as IT;

        // Keep a single formatted print within the remaining event budget on the current
        // control-flow path, while still leaving room for EndInstruction.
        let instruction_budget = print_complex_format_instruction_budget(
            self.compile_options.max_trace_event_size as usize,
            self.compile_time_event_bytes_upper_bound,
        );
        let fixed_overhead = std::mem::size_of::<InstructionHeader>()
            + std::mem::size_of::<PrintComplexFormatData>();

        // First pass: accumulate header bytes and static payload, record dynamic args
        let mut arg_count = 0u8;
        let mut headers_total = 0usize;
        let mut static_payload_total = 0usize;
        let mut dynamic_max_lens: Vec<usize> = Vec::new();
        let mut header_lens: Vec<usize> = Vec::with_capacity(complex_args.len());
        for a in complex_args {
            // Header bytes per-arg: var_name_index(2) + type_index(2) + access_path_len(1) + status(1) + data_len(2) + access_path
            let header_len = 2 + 2 + 1 + 1 + 2 + a.access_path.len();
            header_lens.push(header_len);
            headers_total += header_len;

            match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => static_payload_total += bytes.len(),
                ComplexArgSource::AddressValue { .. } => static_payload_total += 8,
                ComplexArgSource::RuntimeRead { .. } => {
                    static_payload_total +=
                        std::cmp::max(a.data_len, DYNAMIC_READ_ERROR_PAYLOAD_LEN)
                }
                ComplexArgSource::ComputedInt { byte_len, .. } => static_payload_total += *byte_len,
                ComplexArgSource::MemDump { len, .. } => {
                    static_payload_total += std::cmp::max(*len, DYNAMIC_READ_ERROR_PAYLOAD_LEN)
                }
                ComplexArgSource::MemDumpDynamic { max_len, .. } => dynamic_max_lens.push(*max_len),
            }
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

        // Second pass: decide effective reserved payload for each arg
        // Default to computed static payload; dynamic args share the event-derived budget
        let mut effective_reserved: Vec<usize> = Vec::with_capacity(complex_args.len());
        for a in complex_args {
            let reserved = match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => bytes.len(),
                ComplexArgSource::AddressValue { .. } => 8,
                ComplexArgSource::RuntimeRead { .. } => {
                    std::cmp::max(a.data_len, DYNAMIC_READ_ERROR_PAYLOAD_LEN)
                }
                ComplexArgSource::ComputedInt { byte_len, .. } => *byte_len,
                ComplexArgSource::MemDump { len, .. } => {
                    std::cmp::max(*len, DYNAMIC_READ_ERROR_PAYLOAD_LEN)
                }
                ComplexArgSource::MemDumpDynamic { .. } => {
                    dynamic_reservations_iter.next().unwrap_or(0)
                }
            };
            effective_reserved.push(reserved);
        }

        // Now compute final inst_data_size using effective reservations
        let total_args_payload: usize =
            header_lens.iter().sum::<usize>() + effective_reserved.iter().sum::<usize>();
        let inst_data_size = std::mem::size_of::<PrintComplexFormatData>() + total_args_payload;
        let total_size = std::mem::size_of::<InstructionHeader>() + inst_data_size;

        // Reserve buffer directly in accumulation buffer to avoid extra copy
        let buffer = self
            .reserve_instruction_region_or_return_zero(total_size as u64)?
            .into_value_after_runtime_returns();

        // Avoid memset; global buffer is zero-initialized

        // Write InstructionHeader
        let inst_type_val = self.context.i8_type().const_int(IT as u8 as u64, false);
        self.builder
            .build_store(buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;
        // data_length at +1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(1, false)],
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

        // Write PrintComplexFormatData at offset 4
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(4, false)],
                    "pcf_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get pcf_data_ptr GEP: {e}"))
                })?
        };

        // format_string_index (u16) at +0
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
        // arg_count (u8) at +2
        let arg_cnt_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(2, false)],
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

        // Start of variable payload after PrintComplexFormatData — use computed effective reservations
        let mut offset = std::mem::size_of::<PrintComplexFormatData>();
        for (arg_index, a) in complex_args.iter().enumerate() {
            // Per-arg reserved payload length
            let reserved_len = effective_reserved[arg_index];

            // Base pointer = data_ptr + offset
            let arg_base = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        data_ptr,
                        &[self.context.i32_type().const_int(offset as u64, false)],
                        "arg_base",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get arg_base GEP: {e}"))
                    })?
            };

            // var_name_index(u16) at +0
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
                        .const_int(a.var_name_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store vni: {e}")))?;

            // type_index(u16) at +2
            let ti_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(2, false)],
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
                        .const_int(a.type_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store ti: {e}")))?;

            // status(u8) at +5
            let apl_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(5, false)],
                        "status_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get status GEP: {e}"))
                    })?
            };
            self.builder
                .build_store(apl_ptr, self.context.i8_type().const_int(0, false))
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

            // access_path_len(u8) at +4
            let apl_ptr2 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(4, false)],
                        "apl_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get apl GEP: {e}")))?
            };
            self.builder
                .build_store(
                    apl_ptr2,
                    self.context
                        .i8_type()
                        .const_int(a.access_path.len() as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store apl: {e}")))?;

            // access_path bytes at +6..+6+len
            for (i, b) in a.access_path.iter().enumerate() {
                let byte_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            arg_base,
                            &[self.context.i32_type().const_int((6 + i) as u64, false)],
                            &format!("ap_byte_{i}"),
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get ap byte GEP: {e}"))
                        })?
                };
                self.builder
                    .build_store(byte_ptr, self.context.i8_type().const_int(*b as u64, false))
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store ap byte: {e}"))
                    })?;
            }

            // data_len(u16) at +6+path_len (store reserved_len to keep layout consistent)
            let dl_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self
                            .context
                            .i32_type()
                            .const_int((6 + a.access_path.len()) as u64, false)],
                        "dl_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get dl GEP: {e}")))?
            };
            let dl_cast = self
                .builder
                .build_pointer_cast(
                    dl_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "dl_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast dl ptr: {e}")))?;
            self.builder
                .build_store(
                    dl_cast,
                    self.context
                        .i16_type()
                        .const_int(reserved_len as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;

            // variable data starts at +8+path_len
            let var_data_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self
                            .context
                            .i32_type()
                            .const_int((8 + a.access_path.len()) as u64, false)],
                        "var_data_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get var_data GEP: {e}"))
                    })?
            };

            // No dynamic cursor; we keep a compile-time offset and use reserved_len for layout

            match &a.source {
                ComplexArgSource::ImmediateBytes { bytes, .. } => {
                    for (i, b) in bytes.iter().enumerate() {
                        let byte_ptr = unsafe {
                            self.builder
                                .build_gep(
                                    self.context.i8_type(),
                                    var_data_ptr,
                                    &[self.context.i32_type().const_int(i as u64, false)],
                                    &format!("var_byte_{i}"),
                                )
                                .map_err(|e| {
                                    CodeGenError::LLVMError(format!(
                                        "Failed to get var byte GEP: {e}"
                                    ))
                                })?
                        };
                        self.builder
                            .build_store(
                                byte_ptr,
                                self.context.i8_type().const_int(*b as u64, false),
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to store var byte: {e}"))
                            })?;
                    }
                    // data_len already set to reserved_len
                }
                ComplexArgSource::MemDump { address, len } => {
                    // Directly probe-read into payload to avoid byte-wise copies
                    let ptr_ty = self.context.ptr_type(AddressSpace::default());
                    let i64_ty = self.context.i64_type();
                    let i32_ty = self.context.i32_type();

                    // Helper: long bpf_probe_read_user(void *dst, u32 size, const void *src)
                    let dst_ptr = self
                        .builder
                        .build_pointer_cast(var_data_ptr, ptr_ty, "md_dst_ptr")
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
                    let len_const = i32_ty.const_int(*len as u64, false);
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
                            aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user
                                as u64,
                            &[dst_ptr.into(), effective_len.into(), src_ptr.into()],
                            i64_ty.into(),
                            "probe_read_user_memdump",
                        )?
                        .into_int_value();

                    // Branch on ret == 0 and offsets available
                    let ok_pred = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::EQ,
                            ret,
                            i64_ty.const_zero(),
                            "md_ok",
                        )
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
                    // ok: nothing extra to do
                    self.builder.position_at_end(ok_b);
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // err: either offsets missing or helper failure
                    self.builder.position_at_end(err_b);
                    let offsets_err_b = self.context.append_basic_block(func, "md_offsets_err");
                    let helper_err_b = self.context.append_basic_block(func, "md_helper_err");
                    self.builder
                        .build_conditional_branch(not_found, offsets_err_b, helper_err_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(offsets_err_b);
                    self.builder
                        .build_store(
                            apl_ptr,
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
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ReadError as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // write errno + addr (12 bytes) to var_data_ptr; reserved sizing ensures this fits
                    let errno_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "errno_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let errno = self.build_errno_i32(ret, "errno_i32")?;
                    self.builder
                        .build_store(errno_ptr, errno)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let addr_ptr_i8 = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[self.context.i32_type().const_int(4, false)],
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
                }
                ComplexArgSource::MemDumpDynamic {
                    address,
                    len_value,
                    max_len: _,
                } => {
                    // Clamp runtime read to effective reserved length for this arg
                    let eff_max_len = effective_reserved[arg_index] as u32;
                    // Read up to rlen=min(len_value, max_len) into helper buffer, then copy bytes into payload
                    let i32_ty = self.context.i32_type();
                    let rlen_i32 = if len_value.get_type().get_bit_width() > 32 {
                        self.builder
                            .build_int_truncate(*len_value, i32_ty, "mdd_len_trunc")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    } else if len_value.get_type().get_bit_width() < 32 {
                        self.builder
                            .build_int_z_extend(*len_value, i32_ty, "mdd_len_zext")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    } else {
                        *len_value
                    };
                    // clamp negative to 0
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

                    // Bound length by the reserved space (already ensures >= 12B when possible)
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

                    // If effective length is zero, mark status and skip read.
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

                    // Zero-length branch: set status=ZeroLength and continue.
                    self.builder.position_at_end(zero_b);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ZeroLength as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Non-zero path: perform probe_read_user directly into var_data_ptr
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
                    // ok: data already in var_data_ptr
                    self.builder.position_at_end(ok_b);
                    self.builder
                        .build_unconditional_branch(cont_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // err: status+errno+addr (clamped by reserved sizing)
                    self.builder.position_at_end(err_b);
                    let offsets_err_b = self.context.append_basic_block(func, "mdd_offsets_err");
                    let helper_err_b = self.context.append_basic_block(func, "mdd_helper_err");
                    self.builder
                        .build_conditional_branch(not_found, offsets_err_b, helper_err_b)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder.position_at_end(offsets_err_b);
                    self.builder
                        .build_store(
                            apl_ptr,
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
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ReadError as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    if eff_max_len >= 4 {
                        let errno_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "mdd_errno_ptr",
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        let errno = self.build_errno_i32(ret, "mdd_errno_i32")?;
                        self.builder
                            .build_store(errno_ptr, errno)
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    }
                    if eff_max_len as usize >= DYNAMIC_READ_ERROR_PAYLOAD_LEN {
                        let addr_ptr_i8 = unsafe {
                            self.builder
                                .build_gep(
                                    self.context.i8_type(),
                                    var_data_ptr,
                                    &[self.context.i32_type().const_int(4, false)],
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
                }
                ComplexArgSource::ComputedInt { value, byte_len } => {
                    // Write computed integer into payload buffer based on requested byte_len
                    // Ensure the destination pointer element type matches the stored value type.
                    match *byte_len {
                        1 => {
                            let bitw = value.get_type().get_bit_width();
                            let v = if bitw == 1 {
                                // Bool: zero-extend to keep 0/1 in payload
                                self.builder
                                    .build_int_z_extend(
                                        *value,
                                        self.context.i8_type(),
                                        "expr_zext_bool_i8",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw < 8 {
                                self.builder
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i8_type(),
                                        "expr_sext_i8",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw > 8 {
                                // wider than i8 -> truncate
                                self.builder
                                    .build_int_truncate(
                                        *value,
                                        self.context.i8_type(),
                                        "expr_trunc_i8",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                // exactly i8
                                *value
                            };
                            // var_data_ptr is i8* already; store directly
                            self.builder
                                .build_store(var_data_ptr, v)
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        }
                        2 => {
                            let bitw = value.get_type().get_bit_width();
                            let v = if bitw < 16 {
                                self.builder
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i16_type(),
                                        "expr_sext_i16",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw > 16 {
                                self.builder
                                    .build_int_truncate(
                                        *value,
                                        self.context.i16_type(),
                                        "expr_trunc_i16",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                // equal width: i16
                                *value
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
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i32_type(),
                                        "expr_sext_i32",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else if bitw > 32 {
                                self.builder
                                    .build_int_truncate(
                                        *value,
                                        self.context.i32_type(),
                                        "expr_trunc_i32",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                // equal width: i32
                                *value
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
                                    .build_int_s_extend(
                                        *value,
                                        self.context.i64_type(),
                                        "expr_sext",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                *value
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
                            // Fallback: write the lowest n bytes little-endian
                            // Truncate/extend to 64-bit, then emit byte stores
                            let v64 = if value.get_type().get_bit_width() < 64 {
                                self.builder
                                    .build_int_z_extend(
                                        *value,
                                        self.context.i64_type(),
                                        "expr_zext_fallback",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                            } else {
                                *value
                            };
                            for i in 0..n {
                                // Extract byte i
                                let shift =
                                    self.context.i64_type().const_int((i * 8) as u64, false);
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
                }
                ComplexArgSource::RuntimeRead {
                    address,
                    dwarf_type,
                    module_for_offsets,
                } => {
                    // Read from user memory at runtime via BPF helper
                    let ptr_type = self.context.ptr_type(AddressSpace::default());
                    let i32_type = self.context.i32_type();
                    let i64_type = self.context.i64_type();
                    let dst_ptr = self
                        .builder
                        .build_bit_cast(var_data_ptr, ptr_type, "dst_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let size_val = i32_type.const_int(a.data_len as u64, false);
                    let src_addr = self.resolve_planned_address(
                        address,
                        Some(apl_ptr),
                        module_for_offsets.as_deref(),
                    )?;
                    let offsets_found = src_addr.offsets_found;
                    let current_fn = self.current_function("compile complex variable read")?;
                    let cont2_block = self.context.append_basic_block(current_fn, "after_read");
                    let skip_block = self.context.append_basic_block(current_fn, "offsets_skip");
                    let found_block = self.context.append_basic_block(current_fn, "offsets_found");
                    self.builder
                        .build_conditional_branch(offsets_found, found_block, skip_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Offsets missing: record failure and continue without helper access.
                    self.builder.position_at_end(skip_block);
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Offsets found: proceed with null check and helper call.
                    self.builder.position_at_end(found_block);
                    let src_ptr = self
                        .builder
                        .build_int_to_ptr(src_addr.value, ptr_type, "src_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // status_ptr was stored in apl_ptr earlier (we named it status_ptr)
                    // Build NULL check
                    let zero64 = i64_type.const_zero();
                    let is_null = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::EQ,
                            src_addr.value,
                            zero64,
                            "is_null",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let null_block = self.context.append_basic_block(current_fn, "null_deref");
                    let read_block = self.context.append_basic_block(current_fn, "read_user");
                    self.builder
                        .build_conditional_branch(is_null, null_block, read_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // NULL path: status=1, keep reserved_len in header, no data write (buffer pre-zeroed)
                    self.builder.position_at_end(null_block);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::NullDeref as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Read path
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

                    // Error branch: status=2 (read_user failed); write errno+addr payload at start; header keeps reserved_len
                    self.builder.position_at_end(err_block);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ReadError as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // write errno at [0..4]
                    let i32_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "errno_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to cast errno ptr: {e}"))
                        })?;
                    self.builder.build_store(i32_ptr, ret).map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store errno: {e}"))
                    })?;
                    // write addr at [4..12]
                    let addr_ptr_i8 = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[i32_type.const_int(4, false)],
                                "addr_ptr_i8",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to get addr gep: {e}"))
                            })?
                    };
                    let addr_ptr = self
                        .builder
                        .build_pointer_cast(
                            addr_ptr_i8,
                            self.context.ptr_type(AddressSpace::default()),
                            "addr_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to cast addr ptr: {e}"))
                        })?;
                    let src_as_i64 = src_addr.value;
                    self.builder
                        .build_store(addr_ptr, src_as_i64)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store addr: {e}"))
                        })?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // OK branch: success or truncated (header keeps reserved_len)
                    self.builder.position_at_end(ok_block);
                    if a.data_len < dwarf_type.size() as usize {
                        self.builder
                            .build_store(
                                apl_ptr,
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
                }
                ComplexArgSource::AddressValue {
                    address,
                    module_for_offsets,
                } => {
                    let addr = self.resolve_planned_address(
                        address,
                        Some(apl_ptr),
                        module_for_offsets.as_deref(),
                    )?;
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
                    // header already set to reserved_len (8)
                }
            }
            // Advance compile-time offset by header_len + reserved_len
            offset += 2 + 2 + 1 + 1 + a.access_path.len() + 2 + reserved_len;
        }

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }
}

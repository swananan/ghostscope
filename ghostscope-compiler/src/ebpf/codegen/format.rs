use super::*;

const COMPLEX_FORMAT_DATA_ARG_COUNT_OFFSET: usize = 2;
const COMPLEX_FORMAT_ARG_TYPE_INDEX_OFFSET: usize = 2;
const COMPLEX_FORMAT_ARG_ACCESS_PATH_LEN_OFFSET: usize = 4;
const COMPLEX_FORMAT_ARG_STATUS_OFFSET: usize = 5;
const COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET: usize = 6;
const COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN: usize = 8;

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

fn complex_format_arg_header_len(arg: &ComplexArg<'_>) -> usize {
    COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN + arg.access_path.len()
}

fn complex_format_static_payload_len(arg: &ComplexArg<'_>) -> Option<usize> {
    match &arg.source {
        ComplexArgSource::ImmediateBytes { bytes } => Some(bytes.len()),
        ComplexArgSource::AddressValue { .. } => Some(8),
        ComplexArgSource::RuntimeRead { .. } => {
            Some(std::cmp::max(arg.data_len, DYNAMIC_READ_ERROR_PAYLOAD_LEN))
        }
        ComplexArgSource::ComputedInt { byte_len, .. } => Some(*byte_len),
        ComplexArgSource::MemDump { len, .. } => {
            Some(std::cmp::max(*len, DYNAMIC_READ_ERROR_PAYLOAD_LEN))
        }
        ComplexArgSource::MemDumpDynamic { .. } => None,
    }
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
        // region and offset 1 is the InstructionHeader data_length field.
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

        // SAFETY: PrintComplexFormatData starts immediately after InstructionHeader
        // at offset 4 in the reserved instruction region.
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
                        .const_int(COMPLEX_FORMAT_DATA_ARG_COUNT_OFFSET as u64, false)],
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
                        .const_int(COMPLEX_FORMAT_ARG_TYPE_INDEX_OFFSET as u64, false)],
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
                        .const_int(COMPLEX_FORMAT_ARG_STATUS_OFFSET as u64, false)],
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
                    &[self
                        .context
                        .i32_type()
                        .const_int(COMPLEX_FORMAT_ARG_ACCESS_PATH_LEN_OFFSET as u64, false)],
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
                        &[self
                            .context
                            .i32_type()
                            .const_int((COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET + i) as u64, false)],
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
                        (COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET + arg.access_path.len()) as u64,
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
                        (COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN + arg.access_path.len()) as u64,
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

    fn emit_complex_format_memdump(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
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
        // SAFETY: read-error payload reserves 12 bytes, so addr starts at byte 4
        // after the errno field.
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
            // SAFETY: eff_max_len is at least the 12-byte read-error payload, so
            // addr starts at byte 4 after errno.
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
        let i32_ptr = self
            .builder
            .build_pointer_cast(
                var_data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "errno_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast errno ptr: {e}")))?;
        self.builder
            .build_store(i32_ptr, ret)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store errno: {e}")))?;
        // SAFETY: read-error payload reserves 12 bytes, so addr starts at byte 4
        // after the errno field.
        let addr_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    var_data_ptr,
                    &[i32_type.const_int(4, false)],
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
                    header_len: COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN + 2,
                    reserved_len: 3,
                },
                ComplexFormatArgLayout {
                    header_len: COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN,
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
        let desired_dynamic_budget = DYNAMIC_READ_ERROR_PAYLOAD_LEN * args.len();
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
                DYNAMIC_READ_ERROR_PAYLOAD_LEN,
                DYNAMIC_READ_ERROR_PAYLOAD_LEN,
            ]
        );
    }
}

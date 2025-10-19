use aya_ebpf_bindings::bindings::bpf_map_type;
use inkwell::context::Context;
use inkwell::debug_info::{AsDIScope, DebugInfoBuilder};
use inkwell::module::Linkage;
use inkwell::module::Module;
use inkwell::values::PointerValue;
use inkwell::AddressSpace;
// AddressSpace was used for pointer-typed BTF encodings; no longer needed after int-field BTF
use std::collections::HashMap;
use tracing::{error, info};

#[derive(Debug, Clone, Copy)]
pub enum BpfMapType {
    Ringbuf,
    Array,
    Hash,
    PerfEventArray,
}

impl BpfMapType {
    fn to_aya_map_type(self) -> u32 {
        match self {
            BpfMapType::Ringbuf => bpf_map_type::BPF_MAP_TYPE_RINGBUF,
            BpfMapType::Array => bpf_map_type::BPF_MAP_TYPE_ARRAY,
            BpfMapType::Hash => bpf_map_type::BPF_MAP_TYPE_HASH,
            BpfMapType::PerfEventArray => bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SizedType {
    pub size: u64, // size in bits
    pub is_none: bool,
}

impl SizedType {
    pub fn none() -> Self {
        SizedType {
            size: 0,
            is_none: true,
        }
    }

    pub fn integer(size: u64) -> Self {
        SizedType {
            size,
            is_none: false,
        }
    }
}

pub struct MapManager<'ctx> {
    context: &'ctx Context,
    map_types: HashMap<String, BpfMapType>,
}

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("Map not found: {0}")]
    MapNotFound(String),

    #[error("Builder error: {0}")]
    Builder(String),

    #[error("Debug info error: {0}")]
    DebugInfo(String),
}

impl From<&str> for MapError {
    fn from(err: &str) -> Self {
        MapError::DebugInfo(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, MapError>;

impl<'ctx> MapManager<'ctx> {
    pub fn new(context: &'ctx Context) -> Self {
        MapManager {
            context,
            map_types: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_map_definition(
        &mut self,
        module: &Module<'ctx>,
        di_builder: &DebugInfoBuilder<'ctx>,
        compile_unit: &inkwell::debug_info::DICompileUnit<'ctx>,
        name: &str,
        map_type: BpfMapType,
        max_entries: u64,
        key_type: SizedType,
        value_type: SizedType,
    ) -> Result<()> {
        info!(
            "Creating map definition: {} (type: {:?}, max_entries: {}, key_type: {:?}, value_type: {:?})",
            name, map_type, max_entries, key_type, value_type
        );

        // Store map type information
        self.map_types.insert(name.to_string(), map_type);

        // Use the original map name directly (like "ringbuf")
        let var_name = name.to_string();
        info!("Map variable name: {}", var_name);

        // Create BPF map definition structure that aya expects
        // Match clang-style: fields are pointers (64-bit); actual values are
        // encoded via BTF pointer-to-array lengths, not via initializers.
        let ptr_ty = self.context.ptr_type(inkwell::AddressSpace::default());

        // Values are conveyed by BTF; initializers can be null pointers.

        // Create struct with appropriate fields based on map type
        // Ringbuf only needs type and max_entries, others need all 4 fields
        let (elements, initializer_values): (Vec<_>, Vec<_>) = match map_type {
            BpfMapType::Ringbuf => (
                vec![ptr_ty.into(), ptr_ty.into()],
                vec![ptr_ty.const_null().into(), ptr_ty.const_null().into()],
            ),
            _ => (
                vec![ptr_ty.into(), ptr_ty.into(), ptr_ty.into(), ptr_ty.into()],
                vec![
                    ptr_ty.const_null().into(),
                    ptr_ty.const_null().into(),
                    ptr_ty.const_null().into(),
                    ptr_ty.const_null().into(),
                ],
            ),
        };
        let struct_type = self.context.struct_type(&elements, false);
        let initializer = struct_type.const_named_struct(&initializer_values);

        // Create BTF type information for the map
        // This is critical for aya to understand the map structure
        let map_di_type = self.create_map_btf_info(
            di_builder,
            compile_unit,
            &var_name,
            map_type,
            max_entries,
            key_type,
            value_type,
        )?;

        // Create the global variable
        let map_var = module.add_global(struct_type, None, &var_name);

        // Set the proper initializer
        map_var.set_initializer(&initializer);

        // Set section to .maps
        map_var.set_section(Some(".maps"));

        // Set linkage to External so aya can find and relocate the map symbols
        // Private linkage hides symbols from relocations, which breaks aya
        map_var.set_linkage(Linkage::External);

        // Associate the global variable with its debug type
        // This ensures the BTF type information is properly linked
        let file = compile_unit.get_file();
        let di_global_variable = di_builder.create_global_variable_expression(
            compile_unit.as_debug_info_scope(), // scope
            &var_name,                          // name
            &var_name,                          // linkage_name
            file,                               // file
            1,                                  // line_no
            map_di_type,                        // ty
            false,                              // is_local_to_unit
            None,                               // expr
            None,                               // decl
            map_var.get_alignment(),            // align_in_bits
        );

        // Attach the debug info to the global variable using proper metadata API
        // The kind_id for "dbg" in LLVM is typically 0
        map_var.set_metadata(di_global_variable.as_metadata_value(self.context), 0);

        let field_count = match map_type {
            BpfMapType::Ringbuf => 2,
            _ => 4,
        };
        info!(
            "Successfully created map: {} with {} fields",
            var_name, field_count
        );
        Ok(())
    }

    pub fn get_map(&self, module: &Module<'ctx>, name: &str) -> Result<PointerValue<'ctx>> {
        let var_name = name.to_string(); // Use direct name like "ringbuf"
        info!("Looking up map: {}", var_name);

        if let Some(map_var) = module.get_global(&var_name) {
            info!("Found map: {}", var_name);
            Ok(map_var.as_pointer_value())
        } else {
            error!("Map not found: {}", var_name);
            Err(MapError::MapNotFound(var_name))
        }
    }

    pub fn create_ringbuf_map(
        &mut self,
        module: &Module<'ctx>,
        di_builder: &DebugInfoBuilder<'ctx>,
        compile_unit: &inkwell::debug_info::DICompileUnit<'ctx>,
        name: &str,
        ringbuf_size: u64,
    ) -> Result<()> {
        // For ringbuf, max_entries is the buffer size in bytes (must be power of 2)
        // The parameter name is kept as perf_rb_pages for backward compatibility,
        // but we now interpret it directly as the ringbuf size in bytes
        let max_entries = ringbuf_size;
        info!("Creating ringbuf map: {} with {} bytes", name, max_entries);
        self.create_map_definition(
            module,
            di_builder,
            compile_unit,
            name,
            BpfMapType::Ringbuf,
            max_entries,
            // Ringbuf map: key_size = 0, value_size = 0 for ringbuf
            SizedType::none(),
            SizedType::none(),
        )
    }

    /// Create PerfEventArray map for event output (fallback when RingBuf not supported)
    pub fn create_perf_event_array_map(
        &mut self,
        module: &Module<'ctx>,
        di_builder: &DebugInfoBuilder<'ctx>,
        compile_unit: &inkwell::debug_info::DICompileUnit<'ctx>,
        name: &str,
    ) -> Result<()> {
        info!("Creating PerfEventArray map: {}", name);
        self.create_map_definition(
            module,
            di_builder,
            compile_unit,
            name,
            BpfMapType::PerfEventArray,
            0, // max_entries = 0 means auto-detect number of CPUs
            // PerfEventArray: key = u32 (CPU index), value = u32 (FD)
            SizedType::integer(32),
            SizedType::integer(32),
        )
    }

    /// Create the per-(pid,module) section offsets map used for ASLR address calculation
    pub fn create_proc_module_offsets_map(
        &mut self,
        module: &Module<'ctx>,
        di_builder: &DebugInfoBuilder<'ctx>,
        compile_unit: &inkwell::debug_info::DICompileUnit<'ctx>,
        name: &str,
        max_entries: u64,
    ) -> Result<()> {
        // Key: {pid:u32, pad:u32, cookie:u64} => 16 bytes => 128 bits
        // Value: {text, rodata, data, bss: u64} => 32 bytes => 256 bits
        self.create_map_definition(
            module,
            di_builder,
            compile_unit,
            name,
            BpfMapType::Hash,
            max_entries,
            SizedType::integer(128),
            SizedType::integer(256),
        )
    }

    pub fn create_event_loss_counter_map(
        &mut self,
        module: &Module<'ctx>,
        di_builder: &DebugInfoBuilder<'ctx>,
        compile_unit: &inkwell::debug_info::DICompileUnit<'ctx>,
        name: &str,
        max_entries: u64,
    ) -> Result<()> {
        info!(
            "Creating event loss counter map: {} with {} max entries",
            name, max_entries
        );
        // For event loss counter, key and value are both integers
        // Key size is sizeof(event_loss_cnt_key_) * 8
        // Value size is sizeof(event_loss_cnt_val_) * 8
        self.create_map_definition(
            module,
            di_builder,
            compile_unit,
            name,
            BpfMapType::Array,
            max_entries,
            SizedType::integer(64), // Assuming event_loss_cnt_key_ is u64
            SizedType::integer(64), // Assuming event_loss_cnt_val_ is u64
        )
    }

    /// Create BTF type information for a BPF map matching clang's output format
    /// This allows aya to understand the map's key and value types
    #[allow(clippy::too_many_arguments)]
    fn create_map_btf_info(
        &self,
        di_builder: &DebugInfoBuilder<'ctx>,
        compile_unit: &inkwell::debug_info::DICompileUnit<'ctx>,
        map_name: &str,
        map_type: BpfMapType,
        max_entries: u64,
        key_type: SizedType,
        value_type: SizedType,
    ) -> Result<inkwell::debug_info::DIType<'ctx>> {
        info!(
            "Creating BTF info for map: {} (type: {:?})",
            map_name, map_type
        );

        // Create basic types needed for the map structure
        let i32_type = di_builder.create_basic_type("int", 32, 0x05, 0)?; // DW_ATE_signed = 0x05

        let file = compile_unit.get_file();
        let scope = compile_unit.as_debug_info_scope();

        // Create the map structure based on map type, matching clang/aya BTF format:
        // fields are pointers to arrays whose nr_elems encode values.
        let map_type_id = map_type.to_aya_map_type();

        // Helper: pointer to array with given element count (encoded in range)
        let mk_ptr_to_array = |name: &str, nr_elems: i64| {
            let range = 0..nr_elems;
            let arr = di_builder.create_array_type(
                i32_type.as_type(),
                64,
                32,
                std::slice::from_ref(&range),
            );
            di_builder.create_pointer_type(name, arr.as_type(), 64, 64, AddressSpace::default())
        };

        let type_ptr = mk_ptr_to_array("type", map_type_id as i64);

        let members = match map_type {
            BpfMapType::Ringbuf => {
                info!("Creating ringbuf BTF with 2 fields (type, max_entries) as pointer-to-array");
                let max_entries_ptr = mk_ptr_to_array("max_entries", max_entries as i64);
                vec![
                    di_builder.create_member_type(
                        scope,
                        "type",
                        file,
                        0,
                        64,
                        64,
                        0,
                        0,
                        type_ptr.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "max_entries",
                        file,
                        0,
                        64,
                        64,
                        64,
                        0,
                        max_entries_ptr.as_type(),
                    ),
                ]
            }
            _ => {
                info!("Creating array/hash BTF with pointer-to-array fields for aya compatibility");
                let key_size_val = if key_type.is_none {
                    0
                } else {
                    (key_type.size / 8) as i64
                };
                let value_size_val = if value_type.is_none {
                    0
                } else {
                    (value_type.size / 8) as i64
                };
                let key_size_ptr = mk_ptr_to_array("key_size", key_size_val);
                let value_size_ptr = mk_ptr_to_array("value_size", value_size_val);
                let max_entries_ptr = mk_ptr_to_array("max_entries", max_entries as i64);
                let mut v = vec![
                    di_builder.create_member_type(
                        scope,
                        "type",
                        file,
                        0,
                        64,
                        64,
                        0,
                        0,
                        type_ptr.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "key_size",
                        file,
                        0,
                        64,
                        64,
                        64,
                        0,
                        key_size_ptr.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "value_size",
                        file,
                        0,
                        64,
                        64,
                        128,
                        0,
                        value_size_ptr.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "max_entries",
                        file,
                        0,
                        64,
                        64,
                        192,
                        0,
                        max_entries_ptr.as_type(),
                    ),
                ];
                // For proc_module_offsets, include optional 'pinning' to signal Aya ByName pinning
                if map_name == "proc_module_offsets" {
                    // ByName is typically encoded as 1 in aya_obj::maps::PinningType
                    let pinning_ptr = mk_ptr_to_array("pinning", 1);
                    v.push(di_builder.create_member_type(
                        scope,
                        "pinning",
                        file,
                        0,
                        64,
                        64,
                        256,
                        0,
                        pinning_ptr.as_type(),
                    ));
                }
                v
            }
        };

        // Convert members to DIType vector
        let member_types: Vec<_> = members.iter().map(|m| m.as_type()).collect();

        // Total structure size: pointers (64-bit) per field
        let (total_size_bits, field_count) = match map_type {
            BpfMapType::Ringbuf => (128, 2), // 2 * 64 bits
            _ => {
                if map_name == "proc_module_offsets" {
                    (320, 5) // include 'pinning'
                } else {
                    (256, 4)
                }
            }
        };

        // Create the map structure type (anonymous like reference)
        let map_struct_type = di_builder.create_struct_type(
            scope,           // scope
            "",              // name - empty for anonymous struct
            file,            // file
            0,               // line_number
            total_size_bits, // size_in_bits
            32,              // align_in_bits
            0,               // flags
            None,            // derived_from
            &member_types,   // elements
            0,               // runtime_lang
            None,            // vtable_holder
            "",              // unique_id
        );

        info!(
            "Created BTF struct type for map: {} with {} fields, {} total bits",
            map_name, field_count, total_size_bits
        );
        Ok(map_struct_type.as_type())
    }

    /// Get ringbuf map by name
    pub fn get_ringbuf_map(&self, module: &Module<'ctx>, name: &str) -> Result<PointerValue<'ctx>> {
        self.get_map(module, name)
    }

    /// Get a perf event array map by name
    pub fn get_perf_map(&self, module: &Module<'ctx>, name: &str) -> Result<PointerValue<'ctx>> {
        self.get_map(module, name)
    }
}

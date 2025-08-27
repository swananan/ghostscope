use inkwell::context::Context;
use inkwell::debug_info::{DebugInfoBuilder, DIType, AsDIScope};
use inkwell::module::Linkage;
use inkwell::module::Module;
use inkwell::types::{BasicTypeEnum, StructType};
use inkwell::values::{GlobalValue, PointerValue};
use inkwell::AddressSpace;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy)]
pub enum BpfMapType {
    Ringbuf,
    Array,
    Hash,
    PerfEventArray,
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
        info!("Creating map definition: {} (type: {:?}, max_entries: {}, key_type: {:?}, value_type: {:?})", 
            name, map_type, max_entries, key_type, value_type);

        // Store map type information
        self.map_types.insert(name.to_string(), map_type);

        // Use the original map name directly (like "ringbuf")
        let var_name = name.to_string();
        info!("Map variable name: {}", var_name);

        // Create BPF map definition structure that aya expects
        // This should match the structure that aya-obj looks for
        let i32_type = self.context.i32_type();
        
        // Map type ID (BPF_MAP_TYPE_RINGBUF = 27, BPF_MAP_TYPE_ARRAY = 2)
        let map_type_id = match map_type {
            BpfMapType::Ringbuf => 27u32,
            BpfMapType::Array => 2u32,
            BpfMapType::Hash => 1u32,
            BpfMapType::PerfEventArray => 4u32,
        };

        // Calculate key and value sizes in bytes (converting from bits)
        let key_size = if key_type.is_none { 0 } else { (key_type.size / 8) as u32 };
        let value_size = if value_type.is_none { 0 } else { (value_type.size / 8) as u32 };

        // Create a simple struct with basic map definition layout
        // Use the standard 4-field layout that most eBPF maps use
        let elements = vec![
            i32_type.into(),    // type (map type)
            i32_type.into(),    // key_size  
            i32_type.into(),    // value_size
            i32_type.into(),    // max_entries
        ];
        let (struct_elements, initializer) = {
            let struct_type = self.context.struct_type(&elements, false);
            // Use zero-initialization - values will come from BTF
            let init = struct_type.const_zero();
            (elements, init)
        };

        let struct_type = self.context.struct_type(&struct_elements, false);

        // Create BTF type information for the map
        // This is critical for aya to understand the map structure
        let map_di_type = self.create_map_btf_info(di_builder, compile_unit, &var_name, map_type, max_entries, key_type, value_type)?;

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
            &var_name,      // name
            &var_name,      // linkage_name
            file,           // file
            1,              // line_no
            map_di_type,    // ty
            false,          // is_local_to_unit
            None,           // expr
            None,           // decl
            map_var.get_alignment(), // align_in_bits
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
        perf_rb_pages: u64,
    ) -> Result<()> {
        // For ringbuf, max_entries should be power of 2 and reasonable size
        // Use 256KB (262144 bytes) which is a common size for eBPF ringbuf
        let max_entries = 256 * 1024; // 262144
        info!(
            "Creating ringbuf map: {} with {} max entries ({} pages)",
            name, max_entries, perf_rb_pages
        );
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
        info!("Creating BTF info for map: {} (type: {:?})", map_name, map_type);

        // Create basic types needed for the map structure
        let i32_type = di_builder.create_basic_type("int", 32, 0x05, 0)?; // DW_ATE_signed = 0x05
        
        let file = compile_unit.get_file();
        let scope = compile_unit.as_debug_info_scope();

        // Create the map structure based on map type, matching clang's BTF format
        // aya expects 'type' field to be a pointer to array where array.len contains the map type
        let map_type_id = match map_type {
            BpfMapType::Ringbuf => 27u32,
            BpfMapType::Array => 2u32,
            BpfMapType::Hash => 1u32,
            BpfMapType::PerfEventArray => 4u32,
        };
        
        // Create array type with nr_elems = map_type_id (this is how aya encodes map types)
        // Use Range<i64> directly to encode the map type
        let array_type = di_builder.create_array_type(
            i32_type.as_type(),  // element_type
            64,                  // size_in_bits  
            32,                  // align_in_bits
            &[0..map_type_id as i64], // Range with map_type_id as count
        );
        
        // Create pointer to this array for the 'type' field
        let type_ptr_type = di_builder.create_pointer_type(
            "type",
            array_type.as_type(),
            64,  // size_in_bits (pointer size)
            64,  // align_in_bits
            AddressSpace::default()
        );

        let members = match map_type {
            BpfMapType::Ringbuf => {
                // Ringbuf maps in clang BTF have only type and max_entries fields
                // This matches the reference program structure
                info!("Creating ringbuf BTF with 2 fields (type, max_entries)");
                
                // Create max_entries array type with proper range
                let max_entries_array = di_builder.create_array_type(
                    i32_type.as_type(),
                    64,
                    32,
                    &[0..max_entries as i64], // Range with max_entries as count
                );
                let max_entries_ptr = di_builder.create_pointer_type(
                    "max_entries",
                    max_entries_array.as_type(),
                    64,
                    64,
                    AddressSpace::default()
                );
                
                vec![
                    di_builder.create_member_type(
                        scope,
                        "type",
                        file,
                        0,    // line_no
                        64,   // size_in_bits (pointer size)
                        64,   // align_in_bits 
                        0,    // offset_in_bits
                        0,    // flags
                        type_ptr_type.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "max_entries", 
                        file,
                        0,    // line_no
                        64,   // size_in_bits (pointer size)
                        64,   // align_in_bits 
                        64,   // offset_in_bits
                        0,    // flags
                        max_entries_ptr.as_type(),
                    ),
                ]
            },
            _ => {
                // Other maps have all fields as pointers to arrays with encoded values
                info!("Creating array/hash BTF with pointer-to-array fields for aya compatibility");
                
                // Create key_size array
                let key_size_value = if key_type.is_none { 0 } else { (key_type.size / 8) as i64 };
                let key_size_array = di_builder.create_array_type(
                    i32_type.as_type(),
                    64,
                    32,
                    &[0..key_size_value], // Range with key_size as count
                );
                let key_size_ptr = di_builder.create_pointer_type(
                    "key_size",
                    key_size_array.as_type(),
                    64,
                    64,
                    AddressSpace::default()
                );

                // Create value_size array
                let value_size_value = if value_type.is_none { 0 } else { (value_type.size / 8) as i64 };
                let value_size_array = di_builder.create_array_type(
                    i32_type.as_type(),
                    64,
                    32,
                    &[0..value_size_value], // Range with value_size as count
                );
                let value_size_ptr = di_builder.create_pointer_type(
                    "value_size",
                    value_size_array.as_type(),
                    64,
                    64,
                    AddressSpace::default()
                );

                // Create max_entries array
                let max_entries_array = di_builder.create_array_type(
                    i32_type.as_type(),
                    64,
                    32,
                    &[0..max_entries as i64], // Range with max_entries as count
                );
                let max_entries_ptr = di_builder.create_pointer_type(
                    "max_entries",
                    max_entries_array.as_type(),
                    64,
                    64,
                    AddressSpace::default()
                );

                vec![
                    di_builder.create_member_type(
                        scope,
                        "type",
                        file,
                        0,    // line_no
                        64,   // size_in_bits (pointer size)
                        64,   // align_in_bits 
                        0,    // offset_in_bits
                        0,    // flags
                        type_ptr_type.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "key_size",
                        file,
                        0,    // line_no
                        64,   // size_in_bits (pointer size)
                        64,   // align_in_bits 
                        64,   // offset_in_bits
                        0,    // flags
                        key_size_ptr.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "value_size",
                        file,
                        0,    // line_no
                        64,   // size_in_bits (pointer size)
                        64,   // align_in_bits 
                        128,  // offset_in_bits
                        0,    // flags
                        value_size_ptr.as_type(),
                    ),
                    di_builder.create_member_type(
                        scope,
                        "max_entries",
                        file,
                        0,    // line_no
                        64,   // size_in_bits (pointer size)
                        64,   // align_in_bits 
                        192,  // offset_in_bits
                        0,    // flags
                        max_entries_ptr.as_type(),
                    ),
                ]
            }
        };

        // Convert members to DIType vector
        let member_types: Vec<_> = members.iter().map(|m| m.as_type()).collect();

        // Calculate total structure size based on number of fields (all pointers now)
        let (total_size_bits, field_count) = match map_type {
            BpfMapType::Ringbuf => (128, 2),  // 2 * 64 bits (pointers)
            _ => (256, 4),   // 4 * 64 bits (pointers)
        };

        // Create the map structure type (anonymous like reference)
        let map_struct_type = di_builder.create_struct_type(
            scope,                   // scope
            "",                      // name - empty for anonymous struct
            file,                    // file
            0,                       // line_number
            total_size_bits,         // size_in_bits
            32,                      // align_in_bits
            0,                       // flags
            None,                    // derived_from
            &member_types,           // elements
            0,                       // runtime_lang
            None,                    // vtable_holder
            "",                      // unique_id
        );

        info!("Created BTF struct type for map: {} with {} fields, {} total bits", 
               map_name, field_count, total_size_bits);
        Ok(map_struct_type.as_type())
    }
}

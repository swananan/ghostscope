use crate::{
    strip_type_aliases, BTreeArrayCapture, BTreeEdgesCapture, BTreeEntryPresentation,
    BTreeFieldPresentation, HashTableBucketOrder, HashTableBucketSource,
    HashTableEntryPresentation, HashTableFieldPresentation, HashTableOccupancy, MemberLayout,
    ResolvedType, Result, StructMember, TypeId, TypeInfo, TypeProjection, TypeProjectionLayout,
    ValueCapturePlan, ValuePresentation, ValueReadPlan, VariableAccessSegment,
};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BTreeLayout {
    pub(crate) map_path: Vec<String>,
    pub(crate) root_path: Vec<String>,
    pub(crate) length_path: Vec<String>,
    pub(crate) kind: BTreeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BTreeKind {
    Map,
    Set,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HashTableLayout {
    pub(crate) entry_type_path: Vec<String>,
    pub(crate) control_path: Vec<String>,
    pub(crate) length_path: Vec<String>,
    pub(crate) bucket_mask_path: Vec<String>,
    pub(crate) occupancy: HashTableOccupancy,
    pub(crate) buckets: HashTableBucketLayout,
    pub(crate) bucket_order: HashTableBucketOrder,
    pub(crate) kind: HashTableKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HashTableBucketLayout {
    Forward { data_path: Vec<String> },
    ReverseFromControl,
    LegacyAfterControl { pointer_tag_mask: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashTableKind {
    Map,
    Set,
}

/// Generic DWARF operations required by Rust-specific value planners.
///
/// The language layer owns producer conventions and standard-library layout
/// validation. The analyzer implements these primitives without exposing its
/// object-file storage to the language layer.
pub(crate) trait RustPlanContext {
    fn project_type(
        &self,
        current: &ResolvedType,
        segment: &VariableAccessSegment,
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection>;

    fn project_member_path(
        &self,
        current: &ResolvedType,
        path: &[String],
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection>;

    fn template_type_parameter(
        &self,
        type_id: TypeId,
        index: usize,
    ) -> Result<Option<ResolvedType>>;

    fn type_alignment(&self, type_id: TypeId) -> Result<Option<u64>>;

    fn tuple_member_layout(
        &self,
        type_id: TypeId,
        aggregate_type: &TypeInfo,
        index: u32,
    ) -> Result<MemberLayout>;

    fn resolve_aggregate_type_in_module(
        &self,
        anchor: TypeId,
        lookup_names: &[&str],
        exact_qualified_name: Option<&str>,
    ) -> Result<Option<ResolvedType>>;
}

pub(crate) fn hash_table_value_read_plan(
    context: &dyn RustPlanContext,
    current: &ResolvedType,
    layout: HashTableLayout,
    type_module_path: Option<&Path>,
) -> Result<Option<ValueReadPlan>> {
    let entry_type_owner =
        context.project_member_path(current, &layout.entry_type_path, type_module_path)?;
    let Some(entry_owner_type_id) = entry_type_owner.resolved_type.identity.layout_dwarf_id()
    else {
        return Ok(None);
    };
    let Some(entry_type) = context.template_type_parameter(entry_owner_type_id, 0)? else {
        return Ok(None);
    };
    if matches!(
        strip_type_aliases(&entry_type.summary),
        TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
    ) {
        return Ok(None);
    }
    let Some(entry_type_id) = entry_type.identity.layout_dwarf_id() else {
        return Ok(None);
    };
    let entry_stride = entry_type.summary.size();
    let field = |index| {
        context
            .tuple_member_layout(entry_type_id, &entry_type.summary, index)
            .ok()
            .map(|field| HashTableFieldPresentation {
                offset: field.offset,
                field_type: Box::new(field.member_type),
            })
    };
    let entry = match layout.kind {
        HashTableKind::Map => {
            let (Some(key), Some(value)) = (field(0), field(1)) else {
                return Ok(None);
            };
            HashTableEntryPresentation::Map { key, value }
        }
        HashTableKind::Set => {
            let Some(value) = field(0) else {
                return Ok(None);
            };
            HashTableEntryPresentation::Set { value }
        }
    };

    let control = context.project_member_path(current, &layout.control_path, type_module_path)?;
    let buckets = match layout.buckets {
        HashTableBucketLayout::Forward { data_path } => {
            let data = context.project_member_path(current, &data_path, type_module_path)?;
            let TypeInfo::PointerType { target_type, .. } =
                strip_type_aliases(&data.resolved_type.summary)
            else {
                return Ok(None);
            };
            if strip_type_aliases(target_type) != strip_type_aliases(&entry_type.summary) {
                return Ok(None);
            }
            HashTableBucketSource::Forward { data }
        }
        HashTableBucketLayout::ReverseFromControl => HashTableBucketSource::ReverseFromControl,
        HashTableBucketLayout::LegacyAfterControl { pointer_tag_mask } => {
            // Rust's allocation uses the pair type's alignment, not its size.
            // Read the concrete DWARF alignment so differently aligned keys
            // and zero-sized types remain data-driven.
            let Some(entry_alignment) = context.type_alignment(entry_type_id)? else {
                return Ok(None);
            };
            if entry_alignment == 0
                || !entry_alignment.is_power_of_two()
                || (entry_stride > 0 && entry_alignment > entry_stride)
            {
                return Ok(None);
            }
            HashTableBucketSource::LegacyAfterControl {
                entry_alignment,
                pointer_tag_mask,
            }
        }
    };
    let length = context.project_member_path(current, &layout.length_path, type_module_path)?;
    let bucket_mask =
        context.project_member_path(current, &layout.bucket_mask_path, type_module_path)?;

    Ok(Some(ValueReadPlan {
        presentation: ValuePresentation::HashTable {
            entry_stride,
            bucket_order: layout.bucket_order,
            occupancy: layout.occupancy,
            entry,
        },
        capture: ValueCapturePlan::IndirectHashTable {
            control,
            length,
            bucket_mask,
            entry_stride,
            occupancy: layout.occupancy,
            buckets,
            bucket_order: layout.bucket_order,
        },
    }))
}

pub(crate) fn btree_value_read_plan<'a>(
    context: &'a dyn RustPlanContext,
    current: &ResolvedType,
    layout: BTreeLayout,
    type_module_path: Option<&'a Path>,
) -> Result<Option<ValueReadPlan>> {
    BTreePlanner {
        context,
        type_module_path,
    }
    .value_read_plan(current, layout)
}

struct BTreePlanner<'a> {
    context: &'a dyn RustPlanContext,
    type_module_path: Option<&'a Path>,
}

impl BTreePlanner<'_> {
    fn value_read_plan(
        &self,
        current: &ResolvedType,
        layout: BTreeLayout,
    ) -> Result<Option<ValueReadPlan>> {
        let map = self.project_member_path(current, &layout.map_path)?;
        let Some(map_type_id) = map.resolved_type.identity.layout_dwarf_id() else {
            return Ok(None);
        };
        let Some(key_type) = self.context.template_type_parameter(map_type_id, 0)? else {
            return Ok(None);
        };
        if matches!(
            strip_type_aliases(&key_type.summary),
            TypeInfo::UnknownType { .. }
        ) {
            return Ok(None);
        }
        let value_type = match layout.kind {
            BTreeKind::Map => {
                let Some(value_type) = self.context.template_type_parameter(map_type_id, 1)? else {
                    return Ok(None);
                };
                if matches!(
                    strip_type_aliases(&value_type.summary),
                    TypeInfo::UnknownType { .. }
                ) {
                    return Ok(None);
                }
                Some(value_type)
            }
            BTreeKind::Set => None,
        };

        let root = self.project_member_path(current, &layout.root_path)?;
        let length = self.project_member_path(current, &layout.length_path)?;
        let Some(root_value) = self.root_value(&root.resolved_type)? else {
            return Ok(None);
        };
        let root_offset = member_projection_offset(&root)?;
        let root_height_inner = self.project_member_path(&root_value, &["height".to_string()])?;
        let root_node_inner = self.project_member_path(&root_value, &["node".to_string()])?;
        let Some(root_pointer_inner) =
            self.project_pointer_wrapper(&root_node_inner.resolved_type)?
        else {
            return Ok(None);
        };
        let root_height = rebase_member_projection(root_offset, root_height_inner)?;
        let root_node_offset = member_projection_offset(&root_node_inner)?;
        let root_pointer = rebase_member_projection(
            root_offset
                .checked_add(root_node_offset)
                .ok_or_else(|| anyhow::anyhow!("B-Tree root node offset overflow"))?,
            root_pointer_inner,
        )?;
        let Some(pointer_size) = pointer_width(&root_pointer.resolved_type.summary) else {
            return Ok(None);
        };
        if !matches!(pointer_size, 4 | 8)
            || !is_unsigned_scalar_of_size(&root_height.resolved_type.summary, pointer_size)
            || !is_unsigned_scalar_of_size(&length.resolved_type.summary, pointer_size)
        {
            return Ok(None);
        }

        let leaf = self.context.project_type(
            &root_pointer.resolved_type,
            &VariableAccessSegment::Dereference,
            self.type_module_path,
        )?;
        let leaf = leaf.resolved_type;
        if !matches!(
            strip_type_aliases(&leaf.summary),
            TypeInfo::StructType { .. }
        ) {
            return Ok(None);
        }
        let node_length = self.project_member_path(&leaf, &["len".to_string()])?;
        if !is_unsigned_scalar(&node_length.resolved_type.summary) {
            return Ok(None);
        }

        let keys = self.project_member_path(&leaf, &["keys".to_string()])?;
        let Some((node_capacity, key_stride, key_element)) =
            self.array_element(&keys.resolved_type)?
        else {
            return Ok(None);
        };
        let keys_offset = member_projection_offset(&keys)?;
        if !embedded_array_fits(leaf.summary.size(), keys_offset, node_capacity, key_stride) {
            return Ok(None);
        }
        let Some(key_value) = self.project_maybe_uninit_value(&key_element, &key_type)? else {
            return Ok(None);
        };
        let key_value_offset = member_projection_offset(&key_value)?;
        if !embedded_value_fits(key_stride, key_value_offset, &key_type.summary) {
            return Ok(None);
        }

        let (entry, values_capture) = match layout.kind {
            BTreeKind::Map => {
                let Some(value_type) = value_type.as_ref() else {
                    return Ok(None);
                };
                let vals = self.project_member_path(&leaf, &["vals".to_string()])?;
                let Some((value_capacity, value_stride, value_element)) =
                    self.array_element(&vals.resolved_type)?
                else {
                    return Ok(None);
                };
                if value_capacity != node_capacity {
                    return Ok(None);
                }
                let values_offset = member_projection_offset(&vals)?;
                if !embedded_array_fits(
                    leaf.summary.size(),
                    values_offset,
                    value_capacity,
                    value_stride,
                ) {
                    return Ok(None);
                }
                let Some(projected_value) =
                    self.project_maybe_uninit_value(&value_element, value_type)?
                else {
                    return Ok(None);
                };
                let value_offset = member_projection_offset(&projected_value)?;
                if !embedded_value_fits(value_stride, value_offset, &value_type.summary) {
                    return Ok(None);
                }
                (
                    BTreeEntryPresentation::Map {
                        key: BTreeFieldPresentation {
                            slot_stride: key_stride,
                            value_offset: key_value_offset,
                            field_type: Box::new(key_type.summary.clone()),
                        },
                        value: BTreeFieldPresentation {
                            slot_stride: value_stride,
                            value_offset,
                            field_type: Box::new(value_type.summary.clone()),
                        },
                    },
                    Some(BTreeArrayCapture {
                        offset: values_offset,
                        slot_stride: value_stride,
                    }),
                )
            }
            BTreeKind::Set => (
                BTreeEntryPresentation::Set {
                    value: BTreeFieldPresentation {
                        slot_stride: key_stride,
                        value_offset: key_value_offset,
                        field_type: Box::new(key_type.summary.clone()),
                    },
                },
                None,
            ),
        };

        let parent = self.project_member_path(&leaf, &["parent".to_string()])?;
        let Some(parent_pointer) = self.parent_pointer(&parent.resolved_type)? else {
            return Ok(None);
        };
        if pointer_width(&parent_pointer.resolved_type.summary) != Some(pointer_size) {
            return Ok(None);
        }
        let internal = self.context.project_type(
            &parent_pointer.resolved_type,
            &VariableAccessSegment::Dereference,
            self.type_module_path,
        )?;
        let internal = internal.resolved_type;
        let internal_leaf = self.project_member_path(&internal, &["data".to_string()])?;
        if !same_layout_type(&internal_leaf.resolved_type, &leaf) {
            return Ok(None);
        }
        let internal_leaf_offset = member_projection_offset(&internal_leaf)?;
        let edges = self.project_member_path(&internal, &["edges".to_string()])?;
        let Some((edge_count, edge_stride, edge_element)) =
            self.array_element(&edges.resolved_type)?
        else {
            return Ok(None);
        };
        if edge_count != node_capacity.checked_add(1).unwrap_or(u64::MAX) {
            return Ok(None);
        }
        let edges_offset = member_projection_offset(&edges)?;
        if !embedded_array_fits(
            internal.summary.size(),
            edges_offset,
            edge_count,
            edge_stride,
        ) {
            return Ok(None);
        }
        let Some(edge_value) = self.project_maybe_uninit_storage(&edge_element)? else {
            return Ok(None);
        };
        let edge_storage_offset = member_projection_offset(&edge_value)?;
        let Some(edge_pointer_inner) = self.project_pointer_wrapper(&edge_value.resolved_type)?
        else {
            return Ok(None);
        };
        if pointer_width(&edge_pointer_inner.resolved_type.summary) != Some(pointer_size) {
            return Ok(None);
        }
        let edge_target = self.context.project_type(
            &edge_pointer_inner.resolved_type,
            &VariableAccessSegment::Dereference,
            self.type_module_path,
        )?;
        if !same_layout_type(&edge_target.resolved_type, &leaf) {
            return Ok(None);
        }
        let edge_pointer_offset = edge_storage_offset
            .checked_add(member_projection_offset(&edge_pointer_inner)?)
            .ok_or_else(|| anyhow::anyhow!("B-Tree edge pointer offset overflow"))?;
        if !embedded_value_fits(
            edge_stride,
            edge_pointer_offset,
            &edge_pointer_inner.resolved_type.summary,
        ) {
            return Ok(None);
        }
        let Some(offset_from_leaf) = edges_offset.checked_sub(internal_leaf_offset) else {
            return Ok(None);
        };

        Ok(Some(ValueReadPlan {
            presentation: ValuePresentation::BTree {
                node_capacity,
                entry,
            },
            capture: ValueCapturePlan::IndirectBTree {
                root_pointer,
                root_height,
                length,
                node_length,
                keys: BTreeArrayCapture {
                    offset: keys_offset,
                    slot_stride: key_stride,
                },
                values: values_capture,
                edges: BTreeEdgesCapture {
                    offset_from_leaf,
                    slot_stride: edge_stride,
                    pointer_offset: edge_pointer_offset,
                    pointer_size,
                    edge_count,
                },
                node_capacity,
            },
        }))
    }

    fn project_member_path(
        &self,
        current: &ResolvedType,
        path: &[String],
    ) -> Result<TypeProjection> {
        self.context
            .project_member_path(current, path, self.type_module_path)
    }

    fn root_value(&self, root: &ResolvedType) -> Result<Option<ResolvedType>> {
        // Rust 1.35's bundled rust-gdb provider reads `map["root"]`
        // directly. Newer providers unwrap an Option niche first. Select the
        // representation from the concrete DIE rather than the compiler
        // version; every member is projected and validated below.
        if member_path_exists(&root.summary, &["node"])
            && member_path_exists(&root.summary, &["height"])
        {
            return Ok(Some(root.clone()));
        }

        let Some(payload) = self.option_payload_type(root)? else {
            return Ok(None);
        };
        if payload.summary.size() != root.summary.size()
            || !member_path_exists(&payload.summary, &["node"])
            || !member_path_exists(&payload.summary, &["height"])
        {
            return Ok(None);
        }
        Ok(Some(payload))
    }

    fn parent_pointer(&self, parent: &ResolvedType) -> Result<Option<TypeProjection>> {
        // Rust 1.35 stores a nullable raw parent pointer. Newer B-Tree nodes
        // use a pointer-niche Option. The pointer target and width remain
        // concrete DWARF checks in both cases.
        if pointer_width(&parent.summary).is_some() {
            return self.project_pointer_wrapper(parent);
        }

        let Some(payload) = self.option_payload_type(parent)? else {
            return Ok(None);
        };
        if payload.summary.size() != parent.summary.size() {
            return Ok(None);
        }
        self.project_pointer_wrapper(&payload)
    }

    fn option_payload_type(&self, option: &ResolvedType) -> Result<Option<ResolvedType>> {
        let Some(type_id) = option.identity.layout_dwarf_id() else {
            return Ok(None);
        };
        if let Some(payload) = self.context.template_type_parameter(type_id, 0)? {
            return Ok(Some(payload));
        }
        let name = match strip_type_aliases(&option.summary) {
            TypeInfo::StructType { name, .. } | TypeInfo::VariantType { name, .. } => name,
            _ => return Ok(None),
        };
        let Some(payload_name) = rust_single_generic_argument(name, "Option") else {
            return Ok(None);
        };
        let short_name = rust_short_qualified_type_name(payload_name);
        self.context.resolve_aggregate_type_in_module(
            type_id,
            &[payload_name, short_name],
            payload_name.contains("::").then_some(payload_name),
        )
    }

    fn array_element(&self, array: &ResolvedType) -> Result<Option<(u64, u64, ResolvedType)>> {
        let TypeInfo::ArrayType {
            element_count: Some(element_count),
            total_size,
            ..
        } = strip_type_aliases(&array.summary)
        else {
            return Ok(None);
        };
        if *element_count == 0 {
            return Ok(None);
        }
        let element = self.context.project_type(
            array,
            &VariableAccessSegment::ArrayIndex(0),
            self.type_module_path,
        )?;
        let element = element.resolved_type;
        if matches!(
            strip_type_aliases(&element.summary),
            TypeInfo::UnknownType { .. }
        ) {
            return Ok(None);
        }
        let stride = element.summary.size();
        let Some(inferred_size) = stride.checked_mul(*element_count) else {
            return Ok(None);
        };
        // Rust array DIEs carry a subrange count but do not always carry a
        // byte size, notably for arrays of zero-sized MaybeUninit values.
        // A concrete element DIE still gives us an exact DWARF-derived stride.
        if total_size.is_some_and(|total_size| total_size != inferred_size) {
            return Ok(None);
        }
        Ok(Some((*element_count, stride, element)))
    }

    fn project_maybe_uninit_value(
        &self,
        wrapper: &ResolvedType,
        expected: &ResolvedType,
    ) -> Result<Option<TypeProjection>> {
        // Rust 1.49 through 1.93 exposes MaybeUninit storage as
        // `value.value`; current nightly adds a tuple `__0` wrapper. Keep both
        // paths, but accept one only when its concrete DIE matches `expected`.
        for path in [&["value", "value", "__0"][..], &["value", "value"][..]] {
            if !member_path_exists(&wrapper.summary, path) {
                continue;
            }
            let path = path
                .iter()
                .map(|field| (*field).to_string())
                .collect::<Vec<_>>();
            let projected = self.project_member_path(wrapper, &path)?;
            if same_layout_type(&projected.resolved_type, expected) {
                return Ok(Some(projected));
            }
        }
        Ok(None)
    }

    fn project_maybe_uninit_storage(
        &self,
        wrapper: &ResolvedType,
    ) -> Result<Option<TypeProjection>> {
        // Edges use the same version-dependent MaybeUninit wrappers as keys
        // and values, then undergo separate pointer and target validation.
        for path in [&["value", "value", "__0"][..], &["value", "value"][..]] {
            if !member_path_exists(&wrapper.summary, path) {
                continue;
            }
            let path = path
                .iter()
                .map(|field| (*field).to_string())
                .collect::<Vec<_>>();
            return self.project_member_path(wrapper, &path).map(Some);
        }
        Ok(None)
    }

    fn project_pointer_wrapper(&self, wrapper: &ResolvedType) -> Result<Option<TypeProjection>> {
        let mut resolved_type = wrapper.clone();
        let mut offset = 0u64;
        for _ in 0..16 {
            if matches!(
                strip_type_aliases(&resolved_type.summary),
                TypeInfo::PointerType { .. }
            ) {
                return Ok(Some(TypeProjection {
                    layout: TypeProjectionLayout::Member { offset },
                    resolved_type,
                }));
            }
            let TypeInfo::StructType { size, members, .. } =
                strip_type_aliases(&resolved_type.summary)
            else {
                return Ok(None);
            };
            // Rust 1.49's BoxedNode/Unique chain uses `ptr`; current NonNull
            // uses `pointer`, and newer transparent wrappers may add `__0`.
            // Every hop is still resolved and range-checked against its DIE.
            let member = ["ptr", "pointer", "__0"]
                .iter()
                .find_map(|name| unique_valid_member(members, name, *size))
                .or_else(|| unique_non_zst_member(members, *size));
            let Some(member) = member else {
                return Ok(None);
            };
            let projected = self.context.project_type(
                &resolved_type,
                &VariableAccessSegment::Field(member.name.clone()),
                self.type_module_path,
            )?;
            offset = offset
                .checked_add(member.offset)
                .ok_or_else(|| anyhow::anyhow!("Rust pointer wrapper offset overflow"))?;
            resolved_type = projected.resolved_type;
        }
        Ok(None)
    }
}

fn member_projection_offset(projection: &TypeProjection) -> Result<u64> {
    match projection.layout {
        TypeProjectionLayout::Member { offset } => Ok(offset),
        ref layout => Err(anyhow::anyhow!(
            "semantic layout expected a member projection, got {layout:?}"
        )),
    }
}

fn rust_single_generic_argument<'a>(name: &'a str, type_name: &str) -> Option<&'a str> {
    let generic_start = name.find('<')?;
    let base = name[..generic_start].rsplit("::").next()?;
    if base != type_name || !name.ends_with('>') {
        return None;
    }
    let argument = &name[generic_start + 1..name.len() - 1];
    (!argument.is_empty()).then_some(argument)
}

fn rust_short_qualified_type_name(name: &str) -> &str {
    let generic_start = name.find('<').unwrap_or(name.len());
    let prefix = &name[..generic_start];
    let start = prefix.rfind("::").map_or(0, |index| index + 2);
    &name[start..]
}

fn rebase_member_projection(base: u64, mut projection: TypeProjection) -> Result<TypeProjection> {
    let offset = base
        .checked_add(member_projection_offset(&projection)?)
        .ok_or_else(|| anyhow::anyhow!("semantic member projection offset overflow"))?;
    projection.layout = TypeProjectionLayout::Member { offset };
    Ok(projection)
}

fn pointer_width(type_info: &TypeInfo) -> Option<u64> {
    match strip_type_aliases(type_info) {
        TypeInfo::PointerType { size, .. } => Some(*size),
        _ => None,
    }
}

fn is_unsigned_scalar(type_info: &TypeInfo) -> bool {
    matches!(
        strip_type_aliases(type_info),
        TypeInfo::BaseType { encoding, .. }
            if *encoding == gimli::DW_ATE_unsigned.0 as u16
                || *encoding == gimli::DW_ATE_unsigned_char.0 as u16
    )
}

fn is_unsigned_scalar_of_size(type_info: &TypeInfo, expected_size: u64) -> bool {
    is_unsigned_scalar(type_info) && type_info.size() == expected_size
}

fn embedded_value_fits(stride: u64, offset: u64, value_type: &TypeInfo) -> bool {
    offset
        .checked_add(value_type.size())
        .is_some_and(|end| end <= stride || (stride == 0 && end == 0))
}

fn embedded_array_fits(container_size: u64, offset: u64, element_count: u64, stride: u64) -> bool {
    element_count
        .checked_mul(stride)
        .and_then(|size| offset.checked_add(size))
        .is_some_and(|end| end <= container_size)
}

fn same_layout_type(left: &ResolvedType, right: &ResolvedType) -> bool {
    let matching_identity = match (
        left.identity.layout_dwarf_id(),
        right.identity.layout_dwarf_id(),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    };
    matching_identity || strip_type_aliases(&left.summary) == strip_type_aliases(&right.summary)
}

fn member_path_exists(mut current: &TypeInfo, path: &[&str]) -> bool {
    for field in path {
        let members = match strip_type_aliases(current) {
            TypeInfo::StructType { members, .. } | TypeInfo::UnionType { members, .. } => members,
            _ => return false,
        };
        let mut matches = members.iter().filter(|member| member.name == *field);
        let Some(member) = matches.next() else {
            return false;
        };
        if matches.next().is_some() {
            return false;
        }
        current = &member.member_type;
    }
    true
}

fn unique_valid_member<'a>(
    members: &'a [StructMember],
    name: &str,
    container_size: u64,
) -> Option<&'a StructMember> {
    let mut matching = members.iter().filter(|member| member.name == name);
    let member = matching.next()?;
    if matching.next().is_some()
        || member.bit_offset.is_some()
        || member.bit_size.is_some()
        || member
            .offset
            .checked_add(member.member_type.size())
            .is_none_or(|end| end > container_size)
    {
        return None;
    }
    Some(member)
}

fn unique_non_zst_member(members: &[StructMember], container_size: u64) -> Option<&StructMember> {
    let mut matching = members.iter().filter(|member| {
        member.member_type.size() > 0
            && member.bit_offset.is_none()
            && member.bit_size.is_none()
            && member
                .offset
                .checked_add(member.member_type.size())
                .is_some_and(|end| end <= container_size)
    });
    let member = matching.next()?;
    matching.next().is_none().then_some(member)
}

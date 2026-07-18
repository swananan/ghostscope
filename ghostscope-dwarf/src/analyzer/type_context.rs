use super::DwarfAnalyzer;
use crate::{
    indexable_element_layout, member_layout, semantics::PlanError, strip_type_aliases,
    CompilationUnitMetadata, CuId, MemberLayout, ModuleId, PcContext, ProjectedValueRead,
    ProjectedValueStep, ProjectedViewField, ProjectedViewFieldCapture, ResolvedType, Result,
    SemanticType, StructMember, TypeId, TypeIdentity, TypeInfo, TypeLayoutError, TypeOrigin,
    TypeProjection, TypeProjectionLayout, ValueCapturePlan, ValueReadPlan, VariableAccessSegment,
    VariableReadPlan,
};
use std::path::Path;

impl DwarfAnalyzer {
    /// Return language and producer metadata for a loaded compilation unit.
    pub fn compilation_unit_metadata(
        &self,
        module: ModuleId,
        cu: CuId,
    ) -> Result<Option<CompilationUnitMetadata>> {
        let module_path = self
            .module_path_for_id(module)
            .ok_or_else(|| anyhow::anyhow!("Semantic module id {module:?} is not loaded"))?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .compilation_unit_metadata(module, cu)
    }

    /// Return language and producer metadata for the CU containing a PC context.
    pub fn compilation_unit_metadata_for_context(
        &self,
        context: &PcContext,
    ) -> Result<Option<CompilationUnitMetadata>> {
        match context.cu {
            Some(cu) => self.compilation_unit_metadata(context.module, cu),
            None => Ok(None),
        }
    }

    /// Resolve the compilation-unit origin for a stable type identity.
    pub fn type_origin(&self, type_id: TypeId) -> Result<Option<TypeOrigin>> {
        if type_id.module != type_id.die.module || type_id.cu != type_id.die.cu {
            return Err(anyhow::anyhow!("inconsistent TypeId identity: {type_id:?}"));
        }
        self.compilation_unit_metadata(type_id.module, type_id.cu)
            .map(|metadata| metadata.map(TypeOrigin::from))
    }

    fn qualified_type_name(&self, type_id: TypeId) -> Result<Option<String>> {
        let module_path = self.module_path_for_id(type_id.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", type_id.module)
        })?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .qualified_type_name(type_id)
    }

    fn type_summary(&self, type_id: TypeId) -> Result<Option<TypeInfo>> {
        let module_path = self.module_path_for_id(type_id.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", type_id.module)
        })?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .type_summary(type_id)
    }

    fn hydrate_projected_type(&self, mut resolved: ResolvedType) -> Result<ResolvedType> {
        // Pointer summaries intentionally stop recursive DWARF expansion with
        // UnknownType. An exact projected TypeId lets us complete that one DIE
        // on demand without name lookup or recursive layout guessing.
        if matches!(
            strip_type_aliases(&resolved.summary),
            TypeInfo::UnknownType { .. }
        ) {
            if let Some(type_id) = resolved.identity.layout_dwarf_id() {
                if let Some(summary) = self.type_summary(type_id)? {
                    resolved.summary = summary;
                    resolved.origin = self.type_origin(type_id)?;
                }
            }
        }
        Ok(resolved)
    }

    fn template_type_parameter(
        &self,
        type_id: TypeId,
        index: usize,
    ) -> Result<Option<ResolvedType>> {
        let module_path = self.module_path_for_id(type_id.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", type_id.module)
        })?;
        let parameter = self
            .modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .template_type_parameter(type_id, index)?;
        let Some((parameter_id, summary)) = parameter else {
            return Ok(None);
        };

        Ok(Some(ResolvedType::new(
            summary,
            TypeIdentity::Dwarf(parameter_id),
            self.type_origin(parameter_id)?,
        )))
    }

    fn type_alignment(&self, type_id: TypeId) -> Result<Option<u64>> {
        let module_path = self.module_path_for_id(type_id.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", type_id.module)
        })?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .type_alignment(type_id)
    }

    /// Combine the plan's protocol-compatible type summary with its DWARF origin.
    pub fn semantic_type_for_plan(&self, plan: &VariableReadPlan) -> Result<Option<SemanticType>> {
        let Some(summary) = plan.dwarf_type.clone() else {
            return Ok(None);
        };
        let origin = match plan.type_id {
            Some(type_id) => self.type_origin(type_id)?,
            None => None,
        };
        Ok(Some(SemanticType::new(summary, plan.type_id, origin)))
    }

    /// Combine a read plan's physical type with its stable identity and origin.
    pub fn resolved_type_for_plan(&self, plan: &VariableReadPlan) -> Result<Option<ResolvedType>> {
        self.semantic_type_for_plan(plan)
            .map(|semantic| semantic.map(ResolvedType::from_semantic_type))
    }

    /// Plan constant pointer arithmetic while preserving the projected type identity.
    pub fn plan_pointer_element_index(
        &self,
        plan: &VariableReadPlan,
        index: i64,
    ) -> Result<VariableReadPlan> {
        let segment = VariableAccessSegment::ArrayIndex(index);
        let projected_type_id = match plan.type_id {
            Some(type_id) => self.projected_type_id(type_id, &segment)?,
            None => None,
        };
        let mut projected = plan.plan_pointer_element_index(index)?;
        projected.type_id = projected_type_id;
        Ok(projected)
    }

    /// Resolve a source-level tuple index using an exact DWARF type identity.
    pub fn tuple_member_layout(
        &self,
        type_id: TypeId,
        aggregate_type: &TypeInfo,
        index: u32,
    ) -> Result<MemberLayout> {
        let layout_segment =
            self.layout_access_segment(Some(type_id), &VariableAccessSegment::TupleIndex(index))?;
        let VariableAccessSegment::Field(field) = layout_segment else {
            return Err(anyhow::anyhow!(
                "tuple projection did not resolve to a DWARF member"
            ));
        };

        match member_layout(aggregate_type, &field) {
            Ok(layout) => Ok(layout),
            Err(TypeLayoutError::UnknownMember { type_name, .. }) => {
                Err(PlanError::UnknownTupleIndex { index, type_name }.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Resolve a source-level tuple index by module and aggregate name.
    pub fn tuple_member_layout_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        aggregate_type: &TypeInfo,
        index: u32,
    ) -> Result<MemberLayout> {
        let type_id =
            self.tuple_aggregate_type_id_in_module(module_path.as_ref(), aggregate_type, index)?;
        self.tuple_member_layout(type_id, aggregate_type, index)
    }

    /// Project physical layout, type summary, identity, and origin as one
    /// operation so callers cannot accidentally advance only part of the type.
    pub fn project_resolved_type(
        &self,
        current: &ResolvedType,
        segment: &VariableAccessSegment,
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection> {
        if let Some(mut projection) = current.project_structural(segment) {
            projection.resolved_type = self.hydrate_projected_type(projection.resolved_type)?;
            return Ok(projection);
        }

        let (layout, summary, identity) = match segment {
            VariableAccessSegment::Dereference => {
                let TypeInfo::PointerType { target_type, .. } =
                    strip_type_aliases(&current.summary)
                else {
                    return Err(anyhow::anyhow!(
                        "dereference requires pointer type, got '{}'",
                        current.summary.type_name()
                    ));
                };
                (
                    TypeProjectionLayout::Dereference,
                    target_type.as_ref().clone(),
                    self.project_type_identity(&current.identity, segment)?,
                )
            }
            VariableAccessSegment::ArrayIndex(_) => {
                let element = indexable_element_layout(&current.summary).ok_or_else(|| {
                    anyhow::anyhow!(
                        "array index requires array or pointer type, got '{}'",
                        current.summary.type_name()
                    )
                })?;
                (
                    TypeProjectionLayout::Element {
                        stride: element.stride,
                    },
                    element.element_type,
                    self.project_type_identity(&current.identity, segment)?,
                )
            }
            VariableAccessSegment::Field(field) => {
                let member = member_layout(&current.summary, field)?;
                (
                    TypeProjectionLayout::Member {
                        offset: member.offset,
                    },
                    member.member_type,
                    self.project_type_identity(&current.identity, segment)?,
                )
            }
            VariableAccessSegment::TupleIndex(index) => {
                let aggregate_id = match current.identity.layout_dwarf_id() {
                    Some(type_id) => type_id,
                    None => {
                        let module_path = type_module_path
                            .ok_or(PlanError::TupleIndexMissingTypeIdentity { index: *index })?;
                        self.tuple_aggregate_type_id_in_module(
                            module_path,
                            &current.summary,
                            *index,
                        )?
                    }
                };
                let member = self.tuple_member_layout(aggregate_id, &current.summary, *index)?;
                let identity = self
                    .project_type_id(aggregate_id, segment)?
                    .map(TypeIdentity::Dwarf)
                    .unwrap_or(TypeIdentity::Unknown);
                (
                    TypeProjectionLayout::Member {
                        offset: member.offset,
                    },
                    member.member_type,
                    identity,
                )
            }
        };
        let origin = match identity.underlying_dwarf_id() {
            Some(type_id) => self.type_origin(type_id)?,
            None => None,
        };

        Ok(TypeProjection {
            layout,
            resolved_type: self
                .hydrate_projected_type(ResolvedType::new(summary, identity, origin))?,
        })
    }

    /// Build a semantic capture plan when a source-language adapter recognizes
    /// the current physical type. Unknown values keep the ordinary DWARF path.
    pub fn value_read_plan(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
    ) -> Result<Option<ValueReadPlan>> {
        let qualified_name = match (
            crate::language::requires_dwarf_qualified_name(current),
            current.identity.layout_dwarf_id(),
        ) {
            (true, Some(type_id)) => self.qualified_type_name(type_id)?,
            _ => None,
        };
        let Some(layout) =
            crate::language::resolve_value_layout(current, qualified_name.as_deref())
        else {
            return Ok(None);
        };
        let layout = match layout {
            crate::language::ValueLayout::ProjectedValue {
                value_path,
                presentation,
            } => {
                let value =
                    self.project_resolved_member_path(current, &value_path, type_module_path)?;
                let presentation = match presentation {
                    crate::language::ProjectedValuePresentation::Transparent => {
                        crate::ValuePresentation::Dwarf
                    }
                    crate::language::ProjectedValuePresentation::SingleField {
                        type_name,
                        field_name,
                    } => crate::ValuePresentation::SingleField {
                        type_name: type_name.to_string(),
                        field_name: field_name.to_string(),
                    },
                };
                return Ok(Some(ValueReadPlan {
                    presentation,
                    capture: ValueCapturePlan::ProjectedValue { value },
                }));
            }
            crate::language::ValueLayout::ProjectedStruct(layout) => {
                let root_size = current.summary.size();
                let mut members = Vec::with_capacity(layout.fields.len());
                for field in layout.fields {
                    let projected = self.project_resolved_member_path(
                        current,
                        &field.value_path,
                        type_module_path,
                    )?;
                    let TypeProjectionLayout::Member { offset } = projected.layout else {
                        return Err(anyhow::anyhow!(
                            "semantic struct field produced a non-member projection"
                        ));
                    };
                    let member_type = projected.resolved_type.summary;
                    let member_end = offset
                        .checked_add(member_type.size())
                        .ok_or_else(|| anyhow::anyhow!("semantic struct field end overflow"))?;
                    if member_end > root_size {
                        return Err(anyhow::anyhow!(
                            "semantic struct field '{}' exceeds its DWARF root",
                            field.name
                        ));
                    }
                    members.push(StructMember {
                        name: field.name.to_string(),
                        member_type,
                        offset,
                        bit_offset: None,
                        bit_size: None,
                    });
                }
                let presentation = projected_struct_presentation(layout.presentation);
                let output_type = TypeInfo::StructType {
                    name: layout.type_name.to_string(),
                    size: root_size,
                    members,
                };
                return Ok(Some(ValueReadPlan {
                    presentation,
                    capture: ValueCapturePlan::InlineView { output_type },
                }));
            }
            crate::language::ValueLayout::CompositeStruct(layout) => {
                let mut members = Vec::with_capacity(layout.fields.len());
                let mut fields = Vec::with_capacity(layout.fields.len());
                let mut output_size = 0u64;
                for field in layout.fields {
                    if members
                        .iter()
                        .any(|member: &StructMember| member.name == field.name)
                    {
                        return Err(anyhow::anyhow!(
                            "duplicate semantic struct field '{}'",
                            field.name
                        ));
                    }
                    let value = self.project_resolved_value_path(
                        current,
                        &field.value_path,
                        type_module_path,
                        matches!(
                            field.capture,
                            crate::language::CompositeStructFieldCapture::Address
                        ),
                    )?;
                    let Some(value) = value else {
                        return Ok(None);
                    };
                    let (member_type, capture) = match field.capture {
                        crate::language::CompositeStructFieldCapture::Value(requirement) => {
                            if !projected_value_satisfies(requirement, &value) {
                                return Ok(None);
                            }
                            (
                                value.resolved_type.summary.clone(),
                                ProjectedViewFieldCapture::Value,
                            )
                        }
                        crate::language::CompositeStructFieldCapture::Address => {
                            let Some(member_type) = projected_address_type(&value) else {
                                return Ok(None);
                            };
                            (member_type, ProjectedViewFieldCapture::Address)
                        }
                    };
                    let output_offset = output_size;
                    output_size = output_size
                        .checked_add(member_type.size())
                        .ok_or_else(|| anyhow::anyhow!("semantic struct size overflow"))?;
                    members.push(StructMember {
                        name: field.name.to_string(),
                        member_type,
                        offset: output_offset,
                        bit_offset: None,
                        bit_size: None,
                    });
                    fields.push(ProjectedViewField {
                        output_offset,
                        value,
                        capture,
                    });
                }
                let output_type = TypeInfo::StructType {
                    name: layout.type_name.to_string(),
                    size: output_size,
                    members,
                };
                return Ok(Some(ValueReadPlan {
                    presentation: projected_struct_presentation(layout.presentation),
                    capture: ValueCapturePlan::ProjectedView {
                        output_type,
                        fields,
                    },
                }));
            }
            crate::language::ValueLayout::BTree(layout) => {
                return self.rust_btree_value_read_plan(current, layout, type_module_path);
            }
            crate::language::ValueLayout::HashTable(layout) => {
                let entry_type_owner = self.project_resolved_member_path(
                    current,
                    &layout.entry_type_path,
                    type_module_path,
                )?;
                let Some(entry_owner_type_id) =
                    entry_type_owner.resolved_type.identity.layout_dwarf_id()
                else {
                    return Ok(None);
                };
                let Some(entry_type) = self.template_type_parameter(entry_owner_type_id, 0)? else {
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
                    self.tuple_member_layout(entry_type_id, &entry_type.summary, index)
                        .ok()
                        .map(|field| crate::HashTableFieldPresentation {
                            offset: field.offset,
                            field_type: Box::new(field.member_type),
                        })
                };
                let entry = match layout.kind {
                    crate::language::HashTableKind::Map => {
                        let (Some(key), Some(value)) = (field(0), field(1)) else {
                            return Ok(None);
                        };
                        crate::HashTableEntryPresentation::Map { key, value }
                    }
                    crate::language::HashTableKind::Set => {
                        let Some(value) = field(0) else {
                            return Ok(None);
                        };
                        crate::HashTableEntryPresentation::Set { value }
                    }
                };

                let control = self.project_resolved_member_path(
                    current,
                    &layout.control_path,
                    type_module_path,
                )?;
                let buckets = match layout.buckets {
                    crate::language::HashTableBucketLayout::Forward { data_path } => {
                        let data = self.project_resolved_member_path(
                            current,
                            &data_path,
                            type_module_path,
                        )?;
                        let TypeInfo::PointerType { target_type, .. } =
                            strip_type_aliases(&data.resolved_type.summary)
                        else {
                            return Ok(None);
                        };
                        if strip_type_aliases(target_type)
                            != strip_type_aliases(&entry_type.summary)
                        {
                            return Ok(None);
                        }
                        crate::HashTableBucketSource::Forward { data }
                    }
                    crate::language::HashTableBucketLayout::ReverseFromControl => {
                        crate::HashTableBucketSource::ReverseFromControl
                    }
                    crate::language::HashTableBucketLayout::LegacyAfterControl {
                        pointer_tag_mask,
                    } => {
                        // Rust's allocation uses the pair type's alignment, not
                        // its size. Read the concrete alignment attribute so
                        // differently aligned keys and ZSTs remain data-driven.
                        let Some(entry_alignment) = self.type_alignment(entry_type_id)? else {
                            return Ok(None);
                        };
                        if entry_alignment == 0
                            || !entry_alignment.is_power_of_two()
                            || (entry_stride > 0 && entry_alignment > entry_stride)
                        {
                            return Ok(None);
                        }
                        crate::HashTableBucketSource::LegacyAfterControl {
                            entry_alignment,
                            pointer_tag_mask,
                        }
                    }
                };
                let length = self.project_resolved_member_path(
                    current,
                    &layout.length_path,
                    type_module_path,
                )?;
                let bucket_mask = self.project_resolved_member_path(
                    current,
                    &layout.bucket_mask_path,
                    type_module_path,
                )?;
                return Ok(Some(ValueReadPlan {
                    presentation: crate::ValuePresentation::HashTable {
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
                }));
            }
            crate::language::ValueLayout::IndirectSequence(layout) => layout,
        };
        let data =
            self.project_resolved_member_path(current, &layout.data_path, type_module_path)?;

        let (presentation, element_stride) = match layout.kind {
            crate::language::IndirectSequenceKind::Utf8String => {
                (crate::ValuePresentation::Utf8String, None)
            }
            crate::language::IndirectSequenceKind::ByteString => {
                (crate::ValuePresentation::ByteString, None)
            }
            crate::language::IndirectSequenceKind::PointerTarget => {
                let TypeInfo::PointerType { target_type, .. } =
                    strip_type_aliases(&data.resolved_type.summary)
                else {
                    return Ok(None);
                };
                let element_type = target_type.as_ref().clone();
                if matches!(
                    strip_type_aliases(&element_type),
                    TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
                ) {
                    return Ok(None);
                }
                let element_stride = element_type.size();
                (
                    crate::ValuePresentation::Sequence {
                        element_type: Box::new(element_type),
                        element_stride,
                    },
                    Some(element_stride),
                )
            }
            crate::language::IndirectSequenceKind::TypeParameter { index } => {
                let Some(type_id) = current.identity.layout_dwarf_id() else {
                    return Ok(None);
                };
                let Some(element) = self.template_type_parameter(type_id, index)? else {
                    return Ok(None);
                };
                if matches!(
                    strip_type_aliases(&element.summary),
                    TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
                ) {
                    return Ok(None);
                }
                let element_stride = element.summary.size();
                (
                    crate::ValuePresentation::Sequence {
                        element_type: Box::new(element.summary),
                        element_stride,
                    },
                    Some(element_stride),
                )
            }
        };

        let capture = match layout.addressing {
            crate::language::IndirectSequenceAddressing::Contiguous { length_path } => {
                let length =
                    self.project_resolved_member_path(current, &length_path, type_module_path)?;
                match element_stride {
                    Some(element_stride) => ValueCapturePlan::IndirectSequence {
                        data,
                        length,
                        element_stride,
                    },
                    None => ValueCapturePlan::IndirectBytes { data, length },
                }
            }
            crate::language::IndirectSequenceAddressing::Ring {
                start_path,
                length_path,
                length_kind,
                capacity_path,
            } => {
                let Some(element_stride) = element_stride else {
                    return Ok(None);
                };
                let length =
                    self.project_resolved_member_path(current, &length_path, type_module_path)?;
                if element_stride == 0
                    && matches!(
                        length_kind,
                        crate::language::RingSequenceLengthKind::Explicit
                    )
                {
                    // Physical order is unobservable for zero-sized elements.
                    // Avoid depending on a producer-specific capacity encoding.
                    ValueCapturePlan::IndirectSequence {
                        data,
                        length,
                        element_stride,
                    }
                } else {
                    let start =
                        self.project_resolved_member_path(current, &start_path, type_module_path)?;
                    let capacity = self.project_resolved_member_path(
                        current,
                        &capacity_path,
                        type_module_path,
                    )?;
                    let length = Box::new(match length_kind {
                        crate::language::RingSequenceLengthKind::Explicit => {
                            crate::RingSequenceLength::Explicit(length)
                        }
                        crate::language::RingSequenceLengthKind::End => {
                            crate::RingSequenceLength::End(length)
                        }
                    });
                    ValueCapturePlan::IndirectRingSequence {
                        data,
                        start,
                        length,
                        capacity,
                        element_stride,
                    }
                }
            }
        };

        Ok(Some(ValueReadPlan {
            presentation,
            capture,
        }))
    }

    fn rust_btree_value_read_plan(
        &self,
        current: &ResolvedType,
        layout: crate::language::BTreeLayout,
        type_module_path: Option<&Path>,
    ) -> Result<Option<ValueReadPlan>> {
        let map = self.project_resolved_member_path(current, &layout.map_path, type_module_path)?;
        let Some(map_type_id) = map.resolved_type.identity.layout_dwarf_id() else {
            return Ok(None);
        };
        let Some(key_type) = self.template_type_parameter(map_type_id, 0)? else {
            return Ok(None);
        };
        if matches!(
            strip_type_aliases(&key_type.summary),
            TypeInfo::UnknownType { .. }
        ) {
            return Ok(None);
        }
        let value_type = match layout.kind {
            crate::language::BTreeKind::Map => {
                let Some(value_type) = self.template_type_parameter(map_type_id, 1)? else {
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
            crate::language::BTreeKind::Set => None,
        };

        let root =
            self.project_resolved_member_path(current, &layout.root_path, type_module_path)?;
        let length =
            self.project_resolved_member_path(current, &layout.length_path, type_module_path)?;
        let Some(root_value) = self.rust_btree_root_value(&root.resolved_type)? else {
            return Ok(None);
        };
        let root_offset = member_projection_offset(&root)?;
        let root_height_inner = self.project_resolved_member_path(
            &root_value,
            &["height".to_string()],
            type_module_path,
        )?;
        let root_node_inner = self.project_resolved_member_path(
            &root_value,
            &["node".to_string()],
            type_module_path,
        )?;
        let Some(root_pointer_inner) =
            self.project_rust_pointer_wrapper(&root_node_inner.resolved_type, type_module_path)?
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

        let leaf = self.project_resolved_type(
            &root_pointer.resolved_type,
            &VariableAccessSegment::Dereference,
            type_module_path,
        )?;
        let leaf = leaf.resolved_type;
        if !matches!(
            strip_type_aliases(&leaf.summary),
            TypeInfo::StructType { .. }
        ) {
            return Ok(None);
        }
        let node_length =
            self.project_resolved_member_path(&leaf, &["len".to_string()], type_module_path)?;
        if !is_unsigned_scalar(&node_length.resolved_type.summary) {
            return Ok(None);
        }

        let keys =
            self.project_resolved_member_path(&leaf, &["keys".to_string()], type_module_path)?;
        let Some((node_capacity, key_stride, key_element)) =
            self.btree_array_element(&keys.resolved_type, type_module_path)?
        else {
            return Ok(None);
        };
        let keys_offset = member_projection_offset(&keys)?;
        if !embedded_array_fits(leaf.summary.size(), keys_offset, node_capacity, key_stride) {
            return Ok(None);
        }
        let Some(key_value) =
            self.project_rust_maybe_uninit_value(&key_element, &key_type, type_module_path)?
        else {
            return Ok(None);
        };
        let key_value_offset = member_projection_offset(&key_value)?;
        if !embedded_value_fits(key_stride, key_value_offset, &key_type.summary) {
            return Ok(None);
        }

        let (entry, values_capture) = match layout.kind {
            crate::language::BTreeKind::Map => {
                let Some(value_type) = value_type.as_ref() else {
                    return Ok(None);
                };
                let vals = self.project_resolved_member_path(
                    &leaf,
                    &["vals".to_string()],
                    type_module_path,
                )?;
                let Some((value_capacity, value_stride, value_element)) =
                    self.btree_array_element(&vals.resolved_type, type_module_path)?
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
                let Some(projected_value) = self.project_rust_maybe_uninit_value(
                    &value_element,
                    value_type,
                    type_module_path,
                )?
                else {
                    return Ok(None);
                };
                let value_offset = member_projection_offset(&projected_value)?;
                if !embedded_value_fits(value_stride, value_offset, &value_type.summary) {
                    return Ok(None);
                }
                (
                    crate::BTreeEntryPresentation::Map {
                        key: crate::BTreeFieldPresentation {
                            slot_stride: key_stride,
                            value_offset: key_value_offset,
                            field_type: Box::new(key_type.summary.clone()),
                        },
                        value: crate::BTreeFieldPresentation {
                            slot_stride: value_stride,
                            value_offset,
                            field_type: Box::new(value_type.summary.clone()),
                        },
                    },
                    Some(crate::BTreeArrayCapture {
                        offset: values_offset,
                        slot_stride: value_stride,
                    }),
                )
            }
            crate::language::BTreeKind::Set => (
                crate::BTreeEntryPresentation::Set {
                    value: crate::BTreeFieldPresentation {
                        slot_stride: key_stride,
                        value_offset: key_value_offset,
                        field_type: Box::new(key_type.summary.clone()),
                    },
                },
                None,
            ),
        };

        let parent =
            self.project_resolved_member_path(&leaf, &["parent".to_string()], type_module_path)?;
        let Some(parent_pointer) =
            self.rust_btree_parent_pointer(&parent.resolved_type, type_module_path)?
        else {
            return Ok(None);
        };
        if pointer_width(&parent_pointer.resolved_type.summary) != Some(pointer_size) {
            return Ok(None);
        }
        let internal = self.project_resolved_type(
            &parent_pointer.resolved_type,
            &VariableAccessSegment::Dereference,
            type_module_path,
        )?;
        let internal = internal.resolved_type;
        let internal_leaf =
            self.project_resolved_member_path(&internal, &["data".to_string()], type_module_path)?;
        if !same_layout_type(&internal_leaf.resolved_type, &leaf) {
            return Ok(None);
        }
        let internal_leaf_offset = member_projection_offset(&internal_leaf)?;
        let edges =
            self.project_resolved_member_path(&internal, &["edges".to_string()], type_module_path)?;
        let Some((edge_count, edge_stride, edge_element)) =
            self.btree_array_element(&edges.resolved_type, type_module_path)?
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
        let Some(edge_value) =
            self.project_rust_maybe_uninit_storage(&edge_element, type_module_path)?
        else {
            return Ok(None);
        };
        let edge_storage_offset = member_projection_offset(&edge_value)?;
        let Some(edge_pointer_inner) =
            self.project_rust_pointer_wrapper(&edge_value.resolved_type, type_module_path)?
        else {
            return Ok(None);
        };
        if pointer_width(&edge_pointer_inner.resolved_type.summary) != Some(pointer_size) {
            return Ok(None);
        }
        let edge_target = self.project_resolved_type(
            &edge_pointer_inner.resolved_type,
            &VariableAccessSegment::Dereference,
            type_module_path,
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
            presentation: crate::ValuePresentation::BTree {
                node_capacity,
                entry,
            },
            capture: ValueCapturePlan::IndirectBTree {
                root_pointer,
                root_height,
                length,
                node_length,
                keys: crate::BTreeArrayCapture {
                    offset: keys_offset,
                    slot_stride: key_stride,
                },
                values: values_capture,
                edges: crate::BTreeEdgesCapture {
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

    fn rust_btree_root_value(&self, root: &ResolvedType) -> Result<Option<ResolvedType>> {
        // Rust 1.35's bundled rust-gdb provider reads `map["root"]`
        // directly. Newer providers unwrap an Option niche first. Select the
        // representation from the concrete DIE rather than the compiler
        // version; every member is projected and validated below.
        if member_path_exists(&root.summary, &["node"])
            && member_path_exists(&root.summary, &["height"])
        {
            return Ok(Some(root.clone()));
        }

        let Some(payload) = self.rust_option_payload_type(root)? else {
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

    fn rust_btree_parent_pointer(
        &self,
        parent: &ResolvedType,
        type_module_path: Option<&Path>,
    ) -> Result<Option<TypeProjection>> {
        // Rust 1.35 stores a nullable raw parent pointer. Newer B-Tree nodes
        // use a pointer-niche Option. The pointer target and width remain
        // concrete DWARF checks in both cases.
        if pointer_width(&parent.summary).is_some() {
            return self.project_rust_pointer_wrapper(parent, type_module_path);
        }

        let Some(payload) = self.rust_option_payload_type(parent)? else {
            return Ok(None);
        };
        if payload.summary.size() != parent.summary.size() {
            return Ok(None);
        }
        self.project_rust_pointer_wrapper(&payload, type_module_path)
    }

    fn rust_option_payload_type(&self, option: &ResolvedType) -> Result<Option<ResolvedType>> {
        let Some(type_id) = option.identity.layout_dwarf_id() else {
            return Ok(None);
        };
        if let Some(payload) = self.template_type_parameter(type_id, 0)? {
            return Ok(Some(payload));
        }
        let TypeInfo::StructType { name, .. } = strip_type_aliases(&option.summary) else {
            return Ok(None);
        };
        let Some(payload_name) = rust_single_generic_argument(name, "Option") else {
            return Ok(None);
        };
        self.resolved_named_type_in_module(type_id, payload_name)
    }

    fn resolved_named_type_in_module(
        &self,
        anchor: TypeId,
        qualified_name: &str,
    ) -> Result<Option<ResolvedType>> {
        let module_path = self.module_path_for_id(anchor.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", anchor.module)
        })?;
        let module_data = self
            .modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?;
        let short_name = rust_short_qualified_type_name(qualified_name);
        for candidate in [qualified_name, short_name] {
            let Some(type_id) = module_data.aggregate_type_id_by_name(anchor.module, candidate)
            else {
                continue;
            };
            if qualified_name.contains("::") {
                let Some(actual_name) = self.qualified_type_name(type_id)? else {
                    continue;
                };
                if actual_name != qualified_name {
                    continue;
                }
            }
            let Some(summary) = self.type_summary(type_id)? else {
                continue;
            };
            return Ok(Some(ResolvedType::new(
                summary,
                TypeIdentity::Dwarf(type_id),
                self.type_origin(type_id)?,
            )));
        }
        Ok(None)
    }

    fn btree_array_element(
        &self,
        array: &ResolvedType,
        type_module_path: Option<&Path>,
    ) -> Result<Option<(u64, u64, ResolvedType)>> {
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
        let element = self.project_resolved_type(
            array,
            &VariableAccessSegment::ArrayIndex(0),
            type_module_path,
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

    fn project_rust_maybe_uninit_value(
        &self,
        wrapper: &ResolvedType,
        expected: &ResolvedType,
        type_module_path: Option<&Path>,
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
            let projected = self.project_resolved_member_path(wrapper, &path, type_module_path)?;
            if same_layout_type(&projected.resolved_type, expected) {
                return Ok(Some(projected));
            }
        }
        Ok(None)
    }

    fn project_rust_maybe_uninit_storage(
        &self,
        wrapper: &ResolvedType,
        type_module_path: Option<&Path>,
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
            return self
                .project_resolved_member_path(wrapper, &path, type_module_path)
                .map(Some);
        }
        Ok(None)
    }

    fn project_rust_pointer_wrapper(
        &self,
        wrapper: &ResolvedType,
        type_module_path: Option<&Path>,
    ) -> Result<Option<TypeProjection>> {
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
            let projected = self.project_resolved_type(
                &resolved_type,
                &VariableAccessSegment::Field(member.name.clone()),
                type_module_path,
            )?;
            offset = offset
                .checked_add(member.offset)
                .ok_or_else(|| anyhow::anyhow!("Rust pointer wrapper offset overflow"))?;
            resolved_type = projected.resolved_type;
        }
        Ok(None)
    }

    fn project_resolved_member_path(
        &self,
        current: &ResolvedType,
        path: &[String],
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection> {
        let mut resolved_type = current.clone();
        let mut offset = 0u64;

        for field in path {
            let projected = self.project_resolved_type(
                &resolved_type,
                &VariableAccessSegment::Field(field.clone()),
                type_module_path,
            )?;
            let TypeProjectionLayout::Member {
                offset: member_offset,
            } = projected.layout
            else {
                return Err(anyhow::anyhow!(
                    "semantic member path produced a non-member projection"
                ));
            };
            offset = offset
                .checked_add(member_offset)
                .ok_or_else(|| anyhow::anyhow!("semantic member path offset overflow"))?;
            resolved_type = projected.resolved_type;
        }

        Ok(TypeProjection {
            layout: TypeProjectionLayout::Member { offset },
            resolved_type,
        })
    }

    fn project_resolved_value_path(
        &self,
        current: &ResolvedType,
        path: &[crate::language::ProjectedPathSegment],
        type_module_path: Option<&Path>,
        capture_address: bool,
    ) -> Result<Option<ProjectedValueRead>> {
        let mut resolved_type = current.clone();
        let mut steps = Vec::with_capacity(path.len());

        for (index, segment) in path.iter().enumerate() {
            match segment {
                crate::language::ProjectedPathSegment::Member(field) => {
                    let projected = self.project_semantic_member(
                        &resolved_type,
                        Some(field),
                        type_module_path,
                        capture_address && index + 1 == path.len(),
                    )?;
                    let Some(projected) = projected else {
                        return Ok(None);
                    };
                    let TypeProjectionLayout::Member { offset } = projected.layout else {
                        return Err(anyhow::anyhow!(
                            "semantic value path produced a non-member projection"
                        ));
                    };
                    steps.push(ProjectedValueStep::Member { offset });
                    resolved_type = projected.resolved_type;
                }
                crate::language::ProjectedPathSegment::SoleMember => {
                    let Some(projected) = self.project_semantic_member(
                        &resolved_type,
                        None,
                        type_module_path,
                        false,
                    )?
                    else {
                        return Ok(None);
                    };
                    let TypeProjectionLayout::Member { offset } = projected.layout else {
                        return Err(anyhow::anyhow!(
                            "semantic value path produced a non-member projection"
                        ));
                    };
                    steps.push(ProjectedValueStep::Member { offset });
                    resolved_type = projected.resolved_type;
                }
                crate::language::ProjectedPathSegment::UnwrapScalar => {
                    let mut depth = 0usize;
                    loop {
                        match strip_type_aliases(&resolved_type.summary) {
                            TypeInfo::BaseType { .. } | TypeInfo::PointerType { .. } => break,
                            TypeInfo::StructType { .. } => {
                                // rust-gdb follows the first field until GDB
                                // reports a scalar. Requiring a sole member
                                // avoids guessing through unrelated structs.
                                if depth == 16 {
                                    return Ok(None);
                                }
                                let Some(projected) = self.project_semantic_member(
                                    &resolved_type,
                                    None,
                                    type_module_path,
                                    false,
                                )?
                                else {
                                    return Ok(None);
                                };
                                let TypeProjectionLayout::Member { offset } = projected.layout
                                else {
                                    return Err(anyhow::anyhow!(
                                        "semantic scalar wrapper produced a non-member projection"
                                    ));
                                };
                                steps.push(ProjectedValueStep::Member { offset });
                                resolved_type = projected.resolved_type;
                                depth += 1;
                            }
                            _ => return Ok(None),
                        }
                    }
                }
                crate::language::ProjectedPathSegment::Dereference => {
                    let TypeInfo::PointerType {
                        size: pointer_size, ..
                    } = strip_type_aliases(&resolved_type.summary)
                    else {
                        return Ok(None);
                    };
                    if !matches!(*pointer_size, 4 | 8) {
                        return Ok(None);
                    }
                    let projected = self.project_resolved_type(
                        &resolved_type,
                        &VariableAccessSegment::Dereference,
                        type_module_path,
                    )?;
                    if projected.layout != TypeProjectionLayout::Dereference {
                        return Err(anyhow::anyhow!(
                            "semantic value path produced a non-dereference projection"
                        ));
                    }
                    steps.push(ProjectedValueStep::Dereference {
                        pointer_size: *pointer_size,
                    });
                    resolved_type = projected.resolved_type;
                }
            }
        }

        Ok(Some(ProjectedValueRead {
            steps,
            resolved_type,
        }))
    }

    fn project_semantic_member(
        &self,
        current: &ResolvedType,
        expected_name: Option<&str>,
        type_module_path: Option<&Path>,
        allow_trailing_address: bool,
    ) -> Result<Option<TypeProjection>> {
        let TypeInfo::StructType { size, members, .. } = strip_type_aliases(&current.summary)
        else {
            return Ok(None);
        };
        let member = match expected_name {
            Some(expected_name) => {
                let mut matching = members.iter().filter(|member| member.name == expected_name);
                let Some(member) = matching.next() else {
                    return Ok(None);
                };
                if matching.next().is_some() {
                    return Ok(None);
                }
                member
            }
            None => {
                let [member] = members.as_slice() else {
                    return Ok(None);
                };
                member
            }
        };
        let Some(member_end) = member.offset.checked_add(member.member_type.size()) else {
            return Ok(None);
        };
        // rustc can describe a trailing DST such as `RcInner<str>::value` as a
        // one-byte type at an offset equal to the aggregate's static size. An
        // address capture needs only that DWARF member offset, so permit this
        // exact terminal shape. Value captures still reject the apparent
        // out-of-bounds read, as do members starting anywhere else.
        let is_trailing_address = allow_trailing_address && member.offset == *size;
        if member.bit_offset.is_some()
            || member.bit_size.is_some()
            || (member_end > *size && !is_trailing_address)
        {
            return Ok(None);
        }

        let projected = self.project_resolved_type(
            current,
            &VariableAccessSegment::Field(member.name.clone()),
            type_module_path,
        )?;
        let Some(projected_end) = member
            .offset
            .checked_add(projected.resolved_type.summary.size())
        else {
            return Ok(None);
        };
        if projected_end > *size && !is_trailing_address {
            return Ok(None);
        }
        Ok(Some(projected))
    }

    fn project_type_id(
        &self,
        current: TypeId,
        segment: &VariableAccessSegment,
    ) -> Result<Option<TypeId>> {
        let layout_segment = self.layout_access_segment(Some(current), segment)?;
        self.projected_type_id(current, &layout_segment)
    }

    fn project_type_identity(
        &self,
        current: &TypeIdentity,
        segment: &VariableAccessSegment,
    ) -> Result<TypeIdentity> {
        if let Some(projected) = current.project_structural(segment) {
            return Ok(projected);
        }
        match current {
            TypeIdentity::Dwarf(type_id) => Ok(self
                .project_type_id(*type_id, segment)?
                .map(TypeIdentity::Dwarf)
                .unwrap_or(TypeIdentity::Unknown)),
            TypeIdentity::Synthetic {
                kind: crate::SyntheticTypeKind::Qualified,
                inner,
            } => self.project_type_identity(inner, segment),
            TypeIdentity::Synthetic {
                kind: crate::SyntheticTypeKind::Pointer | crate::SyntheticTypeKind::Array,
                ..
            }
            | TypeIdentity::Unknown => Ok(TypeIdentity::Unknown),
        }
    }

    fn tuple_aggregate_type_id_in_module(
        &self,
        module_path: &Path,
        aggregate_type: &TypeInfo,
        index: u32,
    ) -> Result<TypeId> {
        let module_path = self
            .loaded_module_path_for(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module is not loaded for tuple projection"))?;
        let module = self.module_id_for_path(module_path).ok_or_else(|| {
            anyhow::anyhow!("Module {} has no semantic module id", module_path.display())
        })?;
        let type_name = match strip_type_aliases(aggregate_type) {
            TypeInfo::StructType { name, .. } => name,
            other => {
                return Err(PlanError::UnknownTupleIndex {
                    index,
                    type_name: other.type_name(),
                }
                .into())
            }
        };
        self.modules
            .get(module_path)
            .and_then(|module_data| module_data.aggregate_type_id_by_name(module, type_name))
            .ok_or_else(|| PlanError::TupleIndexMissingTypeIdentity { index }.into())
    }

    pub(super) fn projected_type_id(
        &self,
        current: TypeId,
        segment: &VariableAccessSegment,
    ) -> Result<Option<TypeId>> {
        let module_path = self.module_path_for_id(current.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", current.module)
        })?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .projected_type_id(current, segment)
    }

    pub(super) fn layout_access_segment(
        &self,
        current: Option<TypeId>,
        segment: &VariableAccessSegment,
    ) -> Result<VariableAccessSegment> {
        let VariableAccessSegment::TupleIndex(index) = segment else {
            return Ok(segment.clone());
        };
        let current = current.ok_or(PlanError::TupleIndexMissingTypeIdentity { index: *index })?;
        let origin = self
            .type_origin(current)?
            .ok_or(PlanError::TupleIndexMissingTypeIdentity { index: *index })?;
        crate::language::resolve_access_segment(&origin, segment)
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

fn projected_struct_presentation(
    presentation: crate::language::ProjectedStructPresentation,
) -> crate::ValuePresentation {
    match presentation {
        crate::language::ProjectedStructPresentation::SignedState {
            state_field,
            non_negative_label,
            negative_label,
        } => crate::ValuePresentation::SignedStateStruct {
            state_field: state_field.to_string(),
            non_negative_label: non_negative_label.to_string(),
            negative_label: negative_label.to_string(),
        },
        crate::language::ProjectedStructPresentation::ReferenceCounted {
            strong_field,
            weak_field,
            implicit_weak,
        } => crate::ValuePresentation::ReferenceCountedStruct {
            strong_field: strong_field.to_string(),
            weak_field: weak_field.to_string(),
            implicit_weak,
        },
    }
}

fn projected_address_type(value: &ProjectedValueRead) -> Option<TypeInfo> {
    if matches!(
        strip_type_aliases(&value.resolved_type.summary),
        TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
    ) {
        return None;
    }
    let pointer_size = value.steps.iter().rev().find_map(|step| match step {
        ProjectedValueStep::Dereference { pointer_size } => Some(*pointer_size),
        ProjectedValueStep::Member { .. } => None,
    })?;
    matches!(pointer_size, 4 | 8).then(|| TypeInfo::PointerType {
        target_type: Box::new(value.resolved_type.summary.clone()),
        size: pointer_size,
    })
}

fn projected_value_satisfies(
    requirement: crate::language::ProjectedValueRequirement,
    value: &ProjectedValueRead,
) -> bool {
    let value_type = strip_type_aliases(&value.resolved_type.summary);
    match requirement {
        crate::language::ProjectedValueRequirement::KnownSizedOrZst => match value_type {
            TypeInfo::UnknownType { .. }
            | TypeInfo::OptimizedOut { .. }
            | TypeInfo::ArrayType {
                total_size: None, ..
            } => false,
            TypeInfo::BaseType { name, size: 0, .. } => name == "()",
            TypeInfo::StructType { size: 0, .. }
            | TypeInfo::UnionType { size: 0, .. }
            | TypeInfo::ArrayType {
                total_size: Some(0),
                ..
            } => true,
            type_info => type_info.size() > 0,
        },
        crate::language::ProjectedValueRequirement::SignedPointerSizedInteger => {
            let TypeInfo::BaseType { size, encoding, .. } = value_type else {
                return false;
            };
            let signed = *encoding == gimli::DW_ATE_signed.0 as u16
                || *encoding == gimli::DW_ATE_signed_char.0 as u16;
            let pointer_size = value.steps.iter().rev().find_map(|step| match step {
                ProjectedValueStep::Dereference { pointer_size } => Some(*pointer_size),
                ProjectedValueStep::Member { .. } => None,
            });
            signed && matches!(*size, 4 | 8) && pointer_size == Some(*size)
        }
        crate::language::ProjectedValueRequirement::UnsignedPointerSizedInteger => {
            let TypeInfo::BaseType { size, encoding, .. } = value_type else {
                return false;
            };
            let unsigned = *encoding == gimli::DW_ATE_unsigned.0 as u16
                || *encoding == gimli::DW_ATE_unsigned_char.0 as u16;
            let pointer_size = value.steps.iter().rev().find_map(|step| match step {
                ProjectedValueStep::Dereference { pointer_size } => Some(*pointer_size),
                ProjectedValueStep::Member { .. } => None,
            });
            unsigned && matches!(*size, 4 | 8) && pointer_size == Some(*size)
        }
    }
}

#[cfg(test)]
mod projected_value_tests {
    use super::*;

    fn projected_value(summary: TypeInfo, pointer_size: Option<u64>) -> ProjectedValueRead {
        let steps = pointer_size
            .map(|pointer_size| ProjectedValueStep::Dereference { pointer_size })
            .into_iter()
            .collect();
        ProjectedValueRead {
            steps,
            resolved_type: ResolvedType::new(summary, TypeIdentity::Unknown, None),
        }
    }

    #[test]
    fn known_sized_requirement_distinguishes_zst_from_unknown_layout() {
        let requirement = crate::language::ProjectedValueRequirement::KnownSizedOrZst;
        let unit = projected_value(
            TypeInfo::BaseType {
                name: "()".to_string(),
                size: 0,
                encoding: gimli::DW_ATE_unsigned.0 as u16,
            },
            Some(8),
        );
        let unknown = projected_value(
            TypeInfo::UnknownType {
                name: "T".to_string(),
            },
            Some(8),
        );

        assert!(projected_value_satisfies(requirement, &unit));
        assert!(!projected_value_satisfies(requirement, &unknown));
    }

    #[test]
    fn projected_address_uses_the_dwarf_pointer_width() {
        let target = TypeInfo::ArrayType {
            element_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::DW_ATE_unsigned.0 as u16,
            }),
            element_count: None,
            total_size: None,
        };
        let value = projected_value(target.clone(), Some(8));
        assert_eq!(
            projected_address_type(&value),
            Some(TypeInfo::PointerType {
                target_type: Box::new(target),
                size: 8,
            })
        );
        assert_eq!(
            projected_address_type(&projected_value(value.resolved_type.summary, None)),
            None
        );
    }

    #[test]
    fn signed_state_requirement_uses_dwarf_encoding_and_pointer_width() {
        let requirement = crate::language::ProjectedValueRequirement::SignedPointerSizedInteger;
        let signed = |size, pointer_size| {
            projected_value(
                TypeInfo::BaseType {
                    name: "isize".to_string(),
                    size,
                    encoding: gimli::DW_ATE_signed.0 as u16,
                },
                pointer_size,
            )
        };
        assert!(projected_value_satisfies(requirement, &signed(8, Some(8))));
        assert!(!projected_value_satisfies(requirement, &signed(4, Some(8))));
        assert!(!projected_value_satisfies(requirement, &signed(8, None)));

        let unsigned = projected_value(
            TypeInfo::BaseType {
                name: "usize".to_string(),
                size: 8,
                encoding: gimli::DW_ATE_unsigned.0 as u16,
            },
            Some(8),
        );
        assert!(!projected_value_satisfies(requirement, &unsigned));
    }

    #[test]
    fn unsigned_counter_requirement_uses_dwarf_encoding_and_pointer_width() {
        let requirement = crate::language::ProjectedValueRequirement::UnsignedPointerSizedInteger;
        let unsigned = |size, pointer_size| {
            projected_value(
                TypeInfo::BaseType {
                    name: "usize".to_string(),
                    size,
                    encoding: gimli::DW_ATE_unsigned.0 as u16,
                },
                pointer_size,
            )
        };
        assert!(projected_value_satisfies(
            requirement,
            &unsigned(8, Some(8))
        ));
        assert!(!projected_value_satisfies(
            requirement,
            &unsigned(4, Some(8))
        ));
        assert!(!projected_value_satisfies(requirement, &unsigned(8, None)));

        let signed = projected_value(
            TypeInfo::BaseType {
                name: "isize".to_string(),
                size: 8,
                encoding: gimli::DW_ATE_signed.0 as u16,
            },
            Some(8),
        );
        assert!(!projected_value_satisfies(requirement, &signed));
    }
}

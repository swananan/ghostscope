use super::DwarfAnalyzer;
use crate::{
    indexable_element_layout, member_layout, semantics::PlanError, strip_type_aliases,
    CompilationUnitMetadata, CuId, MemberLayout, ModuleId, PcContext, ResolvedType, Result,
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
        if let Some(projection) = current.project_structural(segment) {
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
            resolved_type: ResolvedType::new(summary, identity, origin),
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
                let presentation = match layout.presentation {
                    crate::language::ProjectedStructPresentation::SignedState {
                        state_field,
                        non_negative_label,
                        negative_label,
                    } => crate::ValuePresentation::SignedStateStruct {
                        state_field: state_field.to_string(),
                        non_negative_label: non_negative_label.to_string(),
                        negative_label: negative_label.to_string(),
                    },
                };
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

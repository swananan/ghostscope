use super::DwarfAnalyzer;
use crate::{
    indexable_element_layout, member_layout, semantics::PlanError, strip_type_aliases,
    CompilationUnitMetadata, CuId, MemberLayout, ModuleId, PcContext, ProjectedValueRead,
    ProjectedValueStep, ResolvedType, Result, SemanticType, TypeId, TypeIdentity, TypeInfo,
    TypeLayoutError, TypeOrigin, TypeProjection, TypeProjectionLayout, ValueAdapterOutcome,
    ValueAdapterReport, ValueAdapterStage, ValueCapturePlan, ValueNestedFieldPlan,
    ValueNestedHashTableFieldPlan, ValueNestedPlan, ValueReadPlan, ValueReadPlanOptions,
    ValueReadPlanResolution, VariableAccessSegment, VariableReadPlan,
};
use ghostscope_protocol::{ValueDiagnostic, ValueDiagnosticReason};
use std::path::Path;

enum ShallowValueReadPlan {
    Applied(Box<ValueReadPlan>),
    NotApplicable,
    Rejected {
        reason: ValueDiagnosticReason,
        detail: String,
    },
}

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

    fn variant_member_resolved_type(
        &self,
        current: TypeId,
        part_index: usize,
        variant_index: usize,
        member_index: usize,
    ) -> Result<Option<ResolvedType>> {
        let module_path = self.module_path_for_id(current.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", current.module)
        })?;
        let type_id = self
            .modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .variant_member_type_id(current, part_index, variant_index, member_index)?;
        let Some(type_id) = type_id else {
            return Ok(None);
        };
        let Some(summary) = self.type_summary(type_id)? else {
            return Ok(None);
        };
        Ok(Some(ResolvedType::new(
            summary,
            TypeIdentity::Dwarf(type_id),
            self.type_origin(type_id)?,
        )))
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
        self.value_read_plan_with_options(
            current,
            type_module_path,
            ValueReadPlanOptions::default(),
        )
    }

    /// Build a semantic capture plan with explicit nesting limits. Consumers
    /// that also need notes when no plan applies should use
    /// [`Self::resolve_value_read_plan_with_options`].
    pub fn value_read_plan_with_options(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
        options: ValueReadPlanOptions,
    ) -> Result<Option<ValueReadPlan>> {
        let mut resolution =
            self.resolve_value_read_plan_with_options(current, type_module_path, options)?;
        if let Some(plan) = &mut resolution.plan {
            plan.diagnostics = resolution.diagnostics;
        }
        Ok(resolution.plan)
    }

    /// Resolve capture and static notes separately. Diagnostic-only aggregates
    /// keep `plan = None`, preserving ordinary address and register reads.
    pub fn resolve_value_read_plan_with_options(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
        options: ValueReadPlanOptions,
    ) -> Result<ValueReadPlanResolution> {
        let report =
            self.explain_value_read_plan_with_options(current, type_module_path, options)?;
        let mut diagnostics = Vec::new();
        let mut plan = match report.outcome {
            ValueAdapterOutcome::NotApplicable => self.aggregate_value_read_plan(
                current,
                type_module_path,
                0,
                options.max_nesting_depth,
                &mut Vec::new(),
                &mut diagnostics,
            ),
            ValueAdapterOutcome::Applied { plan } => Some(*plan),
            ValueAdapterOutcome::Rejected {
                ref stage,
                ref reason,
            } => {
                tracing::debug!(
                    target: "ghostscope_dwarf::value_adapter",
                    adapter = report.adapter.as_deref().unwrap_or("unknown"),
                    source_language = ?report.source_language,
                    type_name = report.type_name,
                    qualified_type_name = ?report.qualified_type_name,
                    producer = ?report.producer.as_ref().map(|producer| producer.raw.as_str()),
                    rustc_version = ?report.rustc_version,
                    dwarf_version = ?report.dwarf_version,
                    ?stage,
                    %reason,
                    "Source-language value adapter rejected target DWARF; using DWARF presentation"
                );
                return Ok(ValueReadPlanResolution {
                    plan: None,
                    diagnostics,
                    rejection: Some(report),
                });
            }
        };
        if let Some(plan) = &mut plan {
            diagnostics.append(&mut plan.diagnostics);
        }
        Ok(ValueReadPlanResolution {
            plan,
            diagnostics,
            rejection: None,
        })
    }

    /// Explain whether a source-language adapter can present this value.
    ///
    /// A rejected report is a normal, conservative fallback rather than an
    /// analysis error. Producer metadata is included only to aid debugging;
    /// target DWARF remains the source of layout truth.
    pub fn explain_value_read_plan(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
    ) -> Result<ValueAdapterReport> {
        self.explain_value_read_plan_with_options(
            current,
            type_module_path,
            ValueReadPlanOptions::default(),
        )
    }

    /// Explain adapter selection with explicit semantic nesting limits.
    pub fn explain_value_read_plan_with_options(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
        options: ValueReadPlanOptions,
    ) -> Result<ValueAdapterReport> {
        let qualified_name = match (
            crate::language::requires_dwarf_qualified_name(current),
            current.identity.layout_dwarf_id(),
        ) {
            (true, Some(type_id)) => self.qualified_type_name(type_id)?,
            _ => None,
        };
        let origin = current.origin.as_ref();
        let mut report = ValueAdapterReport {
            source_language: origin
                .map(|origin| origin.language)
                .unwrap_or(crate::SourceLanguage::Unknown),
            type_name: current.summary.type_name(),
            qualified_type_name: qualified_name,
            adapter: None,
            producer: origin.and_then(|origin| origin.producer.clone()),
            rustc_version: origin.and_then(TypeOrigin::rustc_version),
            dwarf_version: origin.map(|origin| origin.dwarf_version),
            outcome: ValueAdapterOutcome::NotApplicable,
        };

        let (adapter, layout) = match crate::language::resolve_value_layout(
            current,
            report.qualified_type_name.as_deref(),
        ) {
            crate::language::ValueLayoutResolution::NotApplicable => return Ok(report),
            crate::language::ValueLayoutResolution::Rejected { adapter, reason } => {
                report.adapter = Some(adapter.to_string());
                report.outcome = ValueAdapterOutcome::Rejected {
                    stage: ValueAdapterStage::LayoutValidation,
                    reason: reason.to_string(),
                };
                return Ok(report);
            }
            crate::language::ValueLayoutResolution::Applied { adapter, layout } => {
                (adapter, layout)
            }
        };
        report.adapter = Some(adapter.to_string());
        report.outcome = match crate::language::build_value_read_plan(
            self,
            current,
            type_module_path,
            layout,
        )? {
            Some(plan) => {
                let plan = self.enrich_nested_value_read_plan(
                    current,
                    plan,
                    type_module_path,
                    0,
                    options.max_nesting_depth,
                    &mut Vec::new(),
                );
                ValueAdapterOutcome::Applied {
                    plan: Box::new(plan),
                }
            }
            None => ValueAdapterOutcome::Rejected {
                stage: ValueAdapterStage::ReadPlanConstruction,
                reason: concat!(
                    "validated root layout could not form a capture plan because ",
                    "a dependent template type, projection, pointer target, width, ",
                    "or alignment was unavailable or inconsistent in target DWARF"
                )
                .to_string(),
            },
        };
        Ok(report)
    }

    fn value_read_plan_shallow(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
    ) -> Result<ShallowValueReadPlan> {
        let qualified_name = match (
            crate::language::requires_dwarf_qualified_name(current),
            current.identity.layout_dwarf_id(),
        ) {
            (true, Some(type_id)) => self.qualified_type_name(type_id)?,
            _ => None,
        };
        let layout = match crate::language::resolve_value_layout(current, qualified_name.as_deref())
        {
            crate::language::ValueLayoutResolution::Applied { layout, .. } => layout,
            crate::language::ValueLayoutResolution::NotApplicable => {
                return Ok(ShallowValueReadPlan::NotApplicable);
            }
            crate::language::ValueLayoutResolution::Rejected { reason, .. } => {
                return Ok(ShallowValueReadPlan::Rejected {
                    reason: ValueDiagnosticReason::LayoutUnsupported,
                    detail: reason.to_string(),
                });
            }
        };
        Ok(
            match crate::language::build_value_read_plan(self, current, type_module_path, layout)? {
                Some(plan) => ShallowValueReadPlan::Applied(Box::new(plan)),
                None => ShallowValueReadPlan::Rejected {
                    reason: ValueDiagnosticReason::ReadPlanUnsupported,
                    detail: "Dependent debug information could not form a capture plan".to_string(),
                },
            },
        )
    }

    fn try_nested_value_read_plan(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
        depth: usize,
        max_nesting_depth: usize,
        ancestors: &mut Vec<TypeId>,
        diagnostics: &mut Vec<ValueDiagnostic>,
    ) -> Option<ValueReadPlan> {
        let plan = match self.value_read_plan_shallow(current, type_module_path) {
            Ok(ShallowValueReadPlan::Applied(plan)) => *plan,
            Ok(ShallowValueReadPlan::NotApplicable) => {
                return self.aggregate_value_read_plan(
                    current,
                    type_module_path,
                    depth,
                    max_nesting_depth,
                    ancestors,
                    diagnostics,
                );
            }
            Ok(ShallowValueReadPlan::Rejected { reason, detail }) => {
                diagnostics.push(ValueDiagnostic {
                    path: String::new(),
                    type_name: current.summary.type_name(),
                    reason,
                    detail,
                });
                return None;
            }
            Err(error) => {
                tracing::debug!(
                    target: "ghostscope_dwarf::value_adapter",
                    child_type = current.summary.type_name(),
                    %error,
                    "Nested value adapter could not form a child plan; using DWARF presentation"
                );
                diagnostics.push(ValueDiagnostic {
                    path: String::new(),
                    type_name: current.summary.type_name(),
                    reason: ValueDiagnosticReason::ReadPlanUnsupported,
                    detail: error.to_string(),
                });
                return None;
            }
        };
        Some(self.enrich_nested_value_read_plan(
            current,
            plan,
            type_module_path,
            depth,
            max_nesting_depth,
            ancestors,
        ))
    }

    fn aggregate_value_read_plan(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
        depth: usize,
        max_nesting_depth: usize,
        ancestors: &mut Vec<TypeId>,
        diagnostics: &mut Vec<ValueDiagnostic>,
    ) -> Option<ValueReadPlan> {
        let plan =
            crate::language::build_aggregate_value_read_plan(self, current, type_module_path)?;
        let plan = self.enrich_nested_value_read_plan(
            current,
            plan,
            type_module_path,
            depth,
            max_nesting_depth,
            ancestors,
        );
        if plan.nested.is_some() {
            Some(plan)
        } else {
            diagnostics.extend(plan.diagnostics);
            None
        }
    }

    /// Bounded diagnostic-only lookahead. Ordinary structs containing only
    /// physical fields must not acquire a spurious "depth limit" warning.
    /// This never adds a read or follows the runtime pointer graph.
    fn has_semantic_display_descendant(
        &self,
        current: &ResolvedType,
        type_module_path: Option<&Path>,
        remaining: &mut usize,
        visited: &mut Vec<TypeId>,
    ) -> bool {
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        if let Some(id) = current.identity.layout_dwarf_id() {
            if visited.contains(&id) {
                return false;
            }
            visited.push(id);
        }
        match self.value_read_plan_shallow(current, type_module_path) {
            Ok(ShallowValueReadPlan::Applied(_) | ShallowValueReadPlan::Rejected { .. }) => true,
            Ok(ShallowValueReadPlan::NotApplicable) => {
                let Some(plan) = crate::language::build_aggregate_value_read_plan(
                    self,
                    current,
                    type_module_path,
                ) else {
                    return false;
                };
                let mut found = false;
                let mut inspect = |child: &ResolvedType, _: &str| {
                    if !found {
                        found = self.has_semantic_display_descendant(
                            child,
                            type_module_path,
                            remaining,
                            visited,
                        );
                    }
                    None
                };
                let _ = crate::language::build_nested_value_read_plan(
                    self,
                    current,
                    &plan.capture,
                    type_module_path,
                    &mut inspect,
                );
                if found {
                    return true;
                }
                if let ValueCapturePlan::InlineView { fields, .. } = &plan.capture {
                    return fields.iter().any(|field| {
                        self.has_semantic_display_descendant(
                            &field.resolved_type,
                            type_module_path,
                            remaining,
                            visited,
                        )
                    });
                }
                false
            }
            Err(_) => false,
        }
    }

    fn enrich_nested_value_read_plan(
        &self,
        current: &ResolvedType,
        mut plan: ValueReadPlan,
        type_module_path: Option<&Path>,
        depth: usize,
        max_nesting_depth: usize,
        ancestors: &mut Vec<TypeId>,
    ) -> ValueReadPlan {
        let current_id = current.identity.layout_dwarf_id();
        let repeated = current_id.is_some_and(|type_id| ancestors.contains(&type_id));
        let limit = if depth >= max_nesting_depth {
            Some(ValueDiagnosticReason::DepthLimit)
        } else if repeated {
            Some(ValueDiagnosticReason::RecursiveType)
        } else {
            None
        };
        if let Some(type_id) = current_id {
            ancestors.push(type_id);
        }
        let mut diagnostics = Vec::new();
        let mut resolve_nested = |child: &ResolvedType, path: &str| {
            let mut child_diagnostics = Vec::new();
            if let Some(reason) = limit {
                // Use bounded type-only lookahead to avoid warning about plain
                // structs. No additional runtime capture is planned.
                let candidate = self.has_semantic_display_descendant(
                    child,
                    type_module_path,
                    &mut 64,
                    &mut Vec::new(),
                );
                if candidate {
                    diagnostics.push(ValueDiagnostic {
                        path: path.to_string(), type_name: child.summary.type_name(), reason,
                        detail: if reason == ValueDiagnosticReason::DepthLimit {
                            format!("value_adapters.max_nesting_depth = {max_nesting_depth}; deeper contents keep their existing field representation")
                        } else { "Expansion stopped at a repeated DWARF type; deeper contents keep their existing field representation".to_string() },
                    });
                }
                return None;
            }
            let child_plan = self.try_nested_value_read_plan(
                child,
                type_module_path,
                depth + 1,
                max_nesting_depth,
                ancestors,
                &mut child_diagnostics,
            );
            if let Some(plan) = &child_plan {
                child_diagnostics.extend(plan.diagnostics.clone());
            }
            diagnostics.extend(
                child_diagnostics
                    .into_iter()
                    .map(|note| note.prefixed(path)),
            );
            child_plan
        };
        let language_nested = crate::language::build_nested_value_read_plan(
            self,
            current,
            &plan.capture,
            type_module_path,
            &mut resolve_nested,
        );
        let mut build_generic_nested = || match &plan.capture {
            ValueCapturePlan::ProjectedValue { value } => {
                resolve_nested(&value.resolved_type, ".value").map(|value| {
                    ValueNestedPlan::ProjectedValue {
                        value: Box::new(value),
                    }
                })
            }
            ValueCapturePlan::InlineView { fields, .. } => {
                let nested_fields = fields
                    .iter()
                    .enumerate()
                    .filter_map(|(field_index, field)| {
                        let path = plan.field_path(field_index);
                        resolve_nested(&field.resolved_type, &path).map(|value| {
                            ValueNestedFieldPlan {
                                field_index,
                                value: Box::new(value),
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                (!nested_fields.is_empty()).then_some(ValueNestedPlan::ProjectedView {
                    fields: nested_fields,
                })
            }
            ValueCapturePlan::ProjectedView { fields, .. } => {
                let nested_fields = fields
                    .iter()
                    .enumerate()
                    .filter(|(_, field)| field.capture == crate::ProjectedViewFieldCapture::Value)
                    .filter_map(|(field_index, field)| {
                        let path = plan.field_path(field_index);
                        resolve_nested(&field.value.resolved_type, &path).map(|value| {
                            ValueNestedFieldPlan {
                                field_index,
                                value: Box::new(value),
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                (!nested_fields.is_empty()).then_some(ValueNestedPlan::ProjectedView {
                    fields: nested_fields,
                })
            }
            ValueCapturePlan::IndirectSequence { .. }
            | ValueCapturePlan::IndirectRingSequence { .. } => plan
                .sequence_element
                .as_ref()
                .and_then(|element| resolve_nested(element, "[]"))
                .map(|element| ValueNestedPlan::Sequence {
                    element: Box::new(element),
                }),
            ValueCapturePlan::IndirectHashTable { .. } => {
                let nested_fields = plan
                    .hash_table_fields
                    .iter()
                    .filter_map(|field| {
                        let path = plan.hash_field_path(field.field_index);
                        resolve_nested(&field.resolved_type, path).map(|value| {
                            ValueNestedHashTableFieldPlan {
                                field_index: field.field_index,
                                value: Box::new(value),
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                (!nested_fields.is_empty()).then_some(ValueNestedPlan::HashTable {
                    fields: nested_fields,
                })
            }
            _ => None,
        };
        let nested = match language_nested {
            crate::language::NestedValuePlanResolution::NotApplicable => build_generic_nested(),
            crate::language::NestedValuePlanResolution::Handled(plan) => plan,
        };
        if current_id.is_some() {
            ancestors.pop();
        }
        plan.nested = nested;
        plan.diagnostics = diagnostics;
        plan
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

impl crate::language::ValueAdapterContext for DwarfAnalyzer {
    fn project_type(
        &self,
        current: &ResolvedType,
        segment: &VariableAccessSegment,
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection> {
        self.project_resolved_type(current, segment, type_module_path)
    }

    fn project_member_path(
        &self,
        current: &ResolvedType,
        path: &[String],
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection> {
        self.project_resolved_member_path(current, path, type_module_path)
    }

    fn project_value_path(
        &self,
        current: &ResolvedType,
        path: &[crate::language::ProjectedPathSegment],
        type_module_path: Option<&Path>,
        capture_address: bool,
    ) -> Result<Option<ProjectedValueRead>> {
        self.project_resolved_value_path(current, path, type_module_path, capture_address)
    }

    fn template_type_parameter(
        &self,
        type_id: TypeId,
        index: usize,
    ) -> Result<Option<ResolvedType>> {
        DwarfAnalyzer::template_type_parameter(self, type_id, index)
    }

    fn variant_member_resolved_type(
        &self,
        current: TypeId,
        part_index: usize,
        variant_index: usize,
        member_index: usize,
    ) -> Result<Option<ResolvedType>> {
        DwarfAnalyzer::variant_member_resolved_type(
            self,
            current,
            part_index,
            variant_index,
            member_index,
        )
    }

    fn type_alignment(&self, type_id: TypeId) -> Result<Option<u64>> {
        DwarfAnalyzer::type_alignment(self, type_id)
    }

    fn tuple_member_layout(
        &self,
        type_id: TypeId,
        aggregate_type: &TypeInfo,
        index: u32,
    ) -> Result<MemberLayout> {
        DwarfAnalyzer::tuple_member_layout(self, type_id, aggregate_type, index)
    }

    fn project_tuple_member(
        &self,
        current: &ResolvedType,
        index: u32,
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection> {
        DwarfAnalyzer::project_resolved_type(
            self,
            current,
            &VariableAccessSegment::TupleIndex(index),
            type_module_path,
        )
    }

    fn resolve_aggregate_type_in_module(
        &self,
        anchor: TypeId,
        lookup_names: &[&str],
        exact_qualified_name: Option<&str>,
    ) -> Result<Option<ResolvedType>> {
        let module_path = self.module_path_for_id(anchor.module).ok_or_else(|| {
            anyhow::anyhow!("Semantic module id {:?} is not loaded", anchor.module)
        })?;
        let module_data = self
            .modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?;

        for candidate in lookup_names {
            let Some(type_id) = module_data.aggregate_type_id_by_name(anchor.module, candidate)
            else {
                continue;
            };
            if let Some(expected_name) = exact_qualified_name {
                let Some(actual_name) = self.qualified_type_name(type_id)? else {
                    continue;
                };
                if actual_name != expected_name {
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
}

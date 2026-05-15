use super::DwarfAnalyzer;
use crate::{
    core::{ModuleAddress, Provenance, Result},
    semantics::{
        AddressSpaceInfo, PcContext, PcLineInfo, PcRange, PlanError, VariableAccessPath,
        VariableAccessSegment, VariableReadPlan, VisibleVariable, VisibleVariablesResult,
    },
};
use std::path::Path;

impl DwarfAnalyzer {
    /// Resolve a module-address pair into the first PC-centered semantic context.
    ///
    /// Today `ModuleAddress.address` is the module/DWARF PC used by the existing
    /// query APIs, so `pc` and `normalized_pc` intentionally match. Runtime
    /// rebasing details are preserved in `address_space` for future lowering.
    pub fn resolve_pc(&self, module_address: &ModuleAddress) -> Result<PcContext> {
        let module_data = self
            .modules
            .get(&module_address.module_path)
            .ok_or_else(|| {
                anyhow::anyhow!("Module {} not loaded", module_address.module_display())
            })?;
        let module = self
            .module_id_for_path(&module_address.module_path)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Module {} has no semantic module id",
                    module_address.module_display()
                )
            })?;

        let (cu, function, lexical_scopes, inline_chain) = module_data
            .resolve_pc_scopes(module, module_address.address)
            .unwrap_or_else(|error| {
                tracing::debug!(
                    "Failed to resolve semantic PC scopes for {}:0x{:x}: {}",
                    module_address.module_display(),
                    module_address.address,
                    error
                );
                (None, None, Vec::new(), Vec::new())
            });
        let source_location = module_data.lookup_source_location(module_address.address);
        let line = source_location.map(|location| PcLineInfo {
            file_path: location.file_path,
            line_number: location.line_number,
            column: location.column,
            address: location.address,
        });
        let function_name = module_data.find_function_name_by_address(module_address.address);
        let is_inline = module_data.is_inline_at(module_address.address);
        let mapping = module_data.module_mapping();

        Ok(PcContext {
            module,
            pc: module_address.address,
            normalized_pc: module_address.address,
            cu,
            function,
            function_name,
            lexical_scopes,
            inline_chain,
            is_inline,
            line,
            address_space: AddressSpaceInfo {
                module_path: Some(mapping.path.clone()),
                runtime_base: mapping.loaded_address,
                link_base: None,
            },
        })
    }

    /// Return variables visible at a previously resolved PC context.
    pub fn visible_variables(&self, ctx: &PcContext) -> Result<Vec<VisibleVariable>> {
        Ok(self.visible_variables_with_diagnostics(ctx)?.variables)
    }

    /// Return variables visible at a PC context plus non-fatal DWARF diagnostics.
    pub fn visible_variables_with_diagnostics(
        &self,
        ctx: &PcContext,
    ) -> Result<VisibleVariablesResult> {
        let module_address = self.module_address_for_context(ctx)?;

        let (variables, diagnostics) = self
            .modules
            .get(&module_address.module_path)
            .ok_or_else(|| {
                anyhow::anyhow!("Module {} not loaded", module_address.module_display())
            })?
            .get_visible_variables_at_address_best_effort_with_diagnostics(
                ctx.module,
                module_address.address,
            )?;
        let mut variables: Vec<VisibleVariable> = variables
            .into_iter()
            .map(|variable| variable.visible_variable())
            .collect();

        variables.sort_by(|a, b| {
            a.scope_depth
                .cmp(&b.scope_depth)
                .then_with(|| b.is_parameter.cmp(&a.is_parameter))
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(VisibleVariablesResult {
            variables,
            diagnostics,
        })
    }

    pub(super) fn module_address_for_context(&self, ctx: &PcContext) -> Result<ModuleAddress> {
        let module_path = match ctx.address_space.module_path.as_deref() {
            Some(path) => path,
            None => self.module_path_for_id(ctx.module).ok_or_else(|| {
                anyhow::anyhow!("Semantic module id {:?} is not loaded", ctx.module)
            })?,
        };
        Ok(ModuleAddress::new(
            module_path.to_path_buf(),
            ctx.normalized_pc,
        ))
    }

    pub(super) fn is_value_backed_aggregate_access_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<PlanError>()
            .is_some_and(PlanError::is_value_backed_aggregate_access)
    }

    pub(super) fn read_plan_from_variable(
        variable: crate::parser::ParsedVariable,
        provenance: Provenance,
    ) -> VariableReadPlan {
        VariableReadPlan::from_visible_variable(variable.visible_variable(), provenance)
    }

    fn attach_pc_context(ctx: &PcContext, mut plan: VariableReadPlan) -> VariableReadPlan {
        plan.pc_range = Some(PcRange {
            start: ctx.normalized_pc,
            end: ctx.normalized_pc,
        });
        plan.inline_context = ctx.inline_chain.last().and_then(|frame| frame.context);
        plan.module_path = ctx.address_space.module_path.clone();
        plan
    }

    pub(super) fn plan_access_path_with_type_completion(
        &self,
        module_path: &Path,
        mut plan: VariableReadPlan,
        path: &VariableAccessPath,
    ) -> Result<VariableReadPlan> {
        for segment in &path.segments {
            let pointer_type_name = plan.type_name.clone();
            self.complete_unknown_pointer_target_type(module_path, &mut plan, &pointer_type_name);
            plan = plan.plan_access_path(&VariableAccessPath::new(vec![segment.clone()]))?;
            if matches!(segment, VariableAccessSegment::Dereference) {
                self.complete_unknown_pointer_target_type(
                    module_path,
                    &mut plan,
                    &pointer_type_name,
                );
            }
        }

        Ok(plan)
    }

    /// Plan a visible variable by source name at a previously resolved PC context.
    ///
    /// Exact names are preferred over producer-synthesized names like `name@...`.
    pub fn plan_variable_by_name(
        &self,
        ctx: &PcContext,
        name: &str,
    ) -> Result<Option<VariableReadPlan>> {
        let VisibleVariablesResult {
            variables: visible_variables,
            diagnostics,
        } = self.visible_variables_with_diagnostics(ctx)?;

        Self::select_visible_variable_by_name(
            ctx.normalized_pc,
            name,
            visible_variables,
            &diagnostics,
        )
        .map(|variable| {
            variable.map(|variable| {
                Self::attach_pc_context(
                    ctx,
                    VariableReadPlan::from_visible_variable(variable, Provenance::DirectDie),
                )
            })
        })
    }

    pub(super) fn select_visible_variable_by_name(
        pc: u64,
        name: &str,
        visible_variables: Vec<VisibleVariable>,
        diagnostics: &[crate::semantics::VariableQueryDiagnostic],
    ) -> Result<Option<VisibleVariable>> {
        let synthesized_prefix = format!("{name}@");
        let matching_diagnostics = diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.name.as_deref().is_some_and(|diagnostic_name| {
                    diagnostic_name == name || diagnostic_name.starts_with(&synthesized_prefix)
                })
            })
            .collect::<Vec<_>>();

        let exact_matches = visible_variables
            .iter()
            .filter(|variable| variable.name == name)
            .cloned()
            .collect::<Vec<_>>();

        let mut candidates = if exact_matches.is_empty() {
            visible_variables
                .into_iter()
                .filter(|variable| variable.name.starts_with(&synthesized_prefix))
                .collect::<Vec<_>>()
        } else {
            exact_matches
        };

        if candidates.is_empty() {
            if let Some(diagnostic) = matching_diagnostics
                .iter()
                .max_by_key(|diagnostic| diagnostic.scope_depth)
            {
                return Err(anyhow::anyhow!(
                    "Unavailable variable '{name}' at PC 0x{:x}: {}",
                    pc,
                    diagnostic.detail
                ));
            }
            return Ok(None);
        }

        let max_scope_depth = candidates
            .iter()
            .map(|variable| variable.scope_depth)
            .max()
            .unwrap_or(0);
        if let Some(diagnostic) = matching_diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.scope_depth > max_scope_depth)
            .max_by_key(|diagnostic| diagnostic.scope_depth)
        {
            return Err(anyhow::anyhow!(
                "Unavailable variable '{name}' at PC 0x{:x}: {}",
                pc,
                diagnostic.detail
            ));
        }
        candidates.retain(|variable| variable.scope_depth == max_scope_depth);

        if candidates.iter().any(|variable| !variable.is_artificial) {
            candidates.retain(|variable| !variable.is_artificial);
        }

        candidates.dedup();
        if candidates.len() > 1 {
            let names = candidates
                .iter()
                .map(|variable| variable.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow::anyhow!(
                "Ambiguous variable '{name}' at PC 0x{:x}: candidates [{}]",
                pc,
                names
            ));
        }

        Ok(candidates.into_iter().next())
    }

    /// Plan a visible variable by stable variable id at a previously resolved PC context.
    ///
    /// This is the identity-based path for callers that first enumerate
    /// `visible_variables(ctx)` and then request a read plan without relying on
    /// a potentially ambiguous source name.
    pub fn plan_variable(
        &self,
        ctx: &PcContext,
        variable_id: crate::VariableId,
    ) -> Result<Option<VariableReadPlan>> {
        if variable_id.declaration.module != ctx.module {
            return Err(anyhow::anyhow!(
                "VariableId module {:?} does not match PcContext module {:?}",
                variable_id.declaration.module,
                ctx.module
            ));
        }

        let matches = self
            .visible_variables(ctx)?
            .into_iter()
            .filter(|variable| variable.declaration == Some(variable_id.declaration))
            .collect::<Vec<_>>();

        match matches.as_slice() {
            [] => Ok(None),
            [variable] => Ok(Some(Self::attach_pc_context(
                ctx,
                VariableReadPlan::from_visible_variable(variable.clone(), Provenance::DirectDie),
            ))),
            _ => Err(anyhow::anyhow!(
                "Ambiguous VariableId {:?} at PC 0x{:x}: {} visible matches",
                variable_id,
                ctx.normalized_pc,
                matches.len()
            )),
        }
    }

    /// Plan a source-level access path from a visible variable id at a PC context.
    pub fn plan_variable_access(
        &self,
        ctx: &PcContext,
        variable_id: crate::VariableId,
        path: &VariableAccessPath,
    ) -> Result<Option<VariableReadPlan>> {
        let Some(plan) = self.plan_variable(ctx, variable_id)? else {
            return Ok(None);
        };
        let module_path = self
            .module_path_for_id(ctx.module)
            .ok_or_else(|| anyhow::anyhow!("Semantic module id {:?} is not loaded", ctx.module))?
            .to_path_buf();

        self.plan_access_path_with_type_completion(&module_path, plan, path)
            .map(Some)
    }

    /// Plan a source-level access path from a visible variable at a PC context.
    pub fn plan_variable_access_by_name(
        &self,
        ctx: &PcContext,
        name: &str,
        path: &VariableAccessPath,
    ) -> Result<Option<VariableReadPlan>> {
        let Some(plan) = self.plan_variable_by_name(ctx, name)? else {
            return Ok(None);
        };
        let module_path = self
            .module_path_for_id(ctx.module)
            .ok_or_else(|| anyhow::anyhow!("Semantic module id {:?} is not loaded", ctx.module))?
            .to_path_buf();

        self.plan_access_path_with_type_completion(&module_path, plan, path)
            .map(Some)
    }

    /// Return variables visible at a module address as semantic views.
    ///
    /// # Arguments
    /// * `module_address` - Module address containing both module path and address offset
    pub(super) fn visible_variables_at_address(
        &self,
        module_address: &ModuleAddress,
    ) -> Result<Vec<VisibleVariable>> {
        tracing::info!(
            "Looking up variables at address 0x{:x} in module {}",
            module_address.address,
            module_address.module_display()
        );
        let ctx = self.resolve_pc(module_address)?;
        self.visible_variables(&ctx)
    }
}

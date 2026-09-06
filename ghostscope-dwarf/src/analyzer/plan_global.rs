use super::DwarfAnalyzer;
use crate::{
    core::{GlobalVariableInfo, Provenance, Result},
    semantics::{PcContext, VariableAccessPath, VariableReadPlan},
};
use std::path::{Path, PathBuf};

impl DwarfAnalyzer {
    pub(super) fn select_unambiguous_global_binding(
        base: &str,
        mut candidates: Vec<(PathBuf, GlobalVariableInfo)>,
    ) -> Result<Option<(PathBuf, GlobalVariableInfo)>> {
        match candidates.len() {
            0 => Ok(None),
            1 => Ok(candidates.pop()),
            count => {
                let details = candidates
                    .iter()
                    .map(|(module_path, info)| {
                        format!(
                            "{} cu={} die=0x{:x}",
                            module_path.display(),
                            info.unit_offset.0,
                            info.die_offset.0
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(anyhow::anyhow!(
                    "Ambiguous global '{base}': {count} matches [{details}]"
                ))
            }
        }
    }

    pub(super) fn select_global_binding_with_preferred_module(
        base: &str,
        prefer_module: &Path,
        candidates: Vec<(PathBuf, GlobalVariableInfo)>,
    ) -> Result<Option<(PathBuf, GlobalVariableInfo)>> {
        let (preferred, fallback): (Vec<_>, Vec<_>) = candidates
            .into_iter()
            .partition(|(module_path, _)| module_path == prefer_module);
        if !preferred.is_empty() {
            return Self::select_unambiguous_global_binding(base, preferred);
        }

        Self::select_unambiguous_global_binding(base, fallback)
    }

    /// Find global/static variables by name across all loaded modules
    pub fn find_global_variables_by_name(&self, name: &str) -> Vec<(PathBuf, GlobalVariableInfo)> {
        let mut results = Vec::new();
        for (module_path, module_data) in &self.modules {
            let vars = module_data.find_global_variables_by_name_any(name);
            for v in vars {
                results.push((module_path.clone(), v));
            }
        }
        if !results.is_empty() {
            return results;
        }

        // Fallback: scan all globals in each module and match by exact or leaf name
        for (module_path, module_data) in &self.modules {
            let all = module_data.list_all_global_variables();
            for v in all {
                let leaf = v.name.rsplit("::").next().unwrap_or(&v.name).to_string();
                if v.name == name || leaf == name {
                    results.push((module_path.clone(), v));
                }
            }
        }

        results
    }

    /// Bind a global/static declaration before projecting its access path.
    /// Without a PC, duplicate declarations in the preferred module are ambiguous.
    pub fn plan_global_access_read_plan(
        &self,
        prefer_module: &Path,
        base: &str,
        path: &VariableAccessPath,
    ) -> Result<Option<(PathBuf, VariableReadPlan)>> {
        self.plan_global_access_read_plan_in_scope(prefer_module, None, base, path)
    }

    /// Resolve global names in the compilation unit of the traced instruction.
    /// An invalid field on that declaration must not select another CU's variable.
    pub fn plan_global_access_read_plan_at_address(
        &self,
        address: &crate::ModuleAddress,
        base: &str,
        path: &VariableAccessPath,
    ) -> Result<Option<(PathBuf, VariableReadPlan)>> {
        let context = self.resolve_pc(address)?;
        self.plan_global_access_read_plan_in_scope(&address.module_path, Some(&context), base, path)
    }

    fn plan_global_access_read_plan_in_scope(
        &self,
        prefer_module: &Path,
        context: Option<&PcContext>,
        base: &str,
        path: &VariableAccessPath,
    ) -> Result<Option<(PathBuf, VariableReadPlan)>> {
        let mut matches = self.find_global_variables_by_name(base);
        let mut has_unknown_scope = false;
        if let Some(context) = context {
            // The global index also lists static locals. A CU preference must not
            // promote a declaration belonging to another function or lexical block.
            matches.retain(|(module_path, info)| {
                let visibility = self.module_id_for_path(module_path).and_then(|module| {
                    self.modules
                        .get(module_path)?
                        .global_variable_visibility(info, module, context)
                });
                has_unknown_scope |= visibility.is_none();
                visibility != Some(false)
            });
        }
        let prefer_cu = context.filter(|_| !has_unknown_scope).and_then(|context| {
            context
                .inline_chain
                .last()
                .map(|frame| frame.abstract_origin.unwrap_or(frame.concrete_die).cu)
                .or(context.cu)
        });
        if let Some(cu) = prefer_cu {
            let in_scope = |(module_path, info): &(PathBuf, GlobalVariableInfo)| {
                Self::module_paths_equivalent(module_path, prefer_module)
                    && info.unit_offset.0 as u64 == u64::from(cu.0)
            };
            if matches.iter().any(in_scope) {
                matches.retain(in_scope);
            }
        }
        let Some((module_path, info)) =
            Self::select_global_binding_with_preferred_module(base, prefer_module, matches)?
        else {
            return Ok(None);
        };
        let base_plan = self.resolve_variable_read_plan_by_offsets_in_module(
            &module_path,
            info.unit_offset,
            info.die_offset,
            Provenance::Synthesized {
                detail: "global access".to_string(),
            },
        )?;
        let plan = self.plan_access_path_with_type_completion(&module_path, base_plan, path)?;
        Ok(Some((module_path, plan)))
    }

    fn resolve_variable_read_plan_by_offsets_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
        provenance: Provenance,
    ) -> Result<VariableReadPlan> {
        let path_buf = module_path.as_ref().to_path_buf();
        let module = self.module_id_for_path(&path_buf).ok_or_else(|| {
            anyhow::anyhow!("Module {} has no semantic module id", path_buf.display())
        })?;
        if let Some(module_data) = self.modules.get(&path_buf) {
            let items = vec![(cu_off, die_off)];
            let vars = module_data.resolve_variables_by_offsets_at_address(0, &items)?;
            let mut var = vars.into_iter().next().ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to resolve variable at offsets {:?}/{:?} in module {}",
                    cu_off,
                    die_off,
                    path_buf.display()
                )
            })?;
            module_data.attach_variable_identity(module, cu_off, die_off, &mut var);
            if var.dwarf_type.is_none() {
                if let Some(ti) = module_data.shallow_type_for_variable_offsets(cu_off, die_off) {
                    var.type_name = ti.type_name();
                    var.dwarf_type = Some(ti);
                }
            }
            let mut plan = Self::read_plan_from_variable(var, provenance);
            plan.module_path = Some(path_buf);
            Ok(plan)
        } else {
            Err(anyhow::anyhow!(
                "Module {} not loaded",
                module_path.as_ref().display()
            ))
        }
    }

    /// List all global/static variables with usable addresses across all loaded modules
    pub fn list_all_global_variables(&self) -> Vec<(PathBuf, GlobalVariableInfo)> {
        let mut results = Vec::new();
        for (module_path, module_data) in &self.modules {
            for v in module_data.list_all_global_variables() {
                results.push((module_path.clone(), v));
            }
        }
        results
    }
}

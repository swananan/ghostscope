use super::DwarfAnalyzer;
use crate::{
    core::{GlobalVariableInfo, Provenance, Result},
    semantics::{VariableAccessPath, VariableReadPlan},
};
use std::path::{Path, PathBuf};

impl DwarfAnalyzer {
    pub(super) fn select_unambiguous_global_plan(
        base: &str,
        mut candidates: Vec<(PathBuf, VariableReadPlan)>,
    ) -> Result<Option<(PathBuf, VariableReadPlan)>> {
        match candidates.len() {
            0 => Ok(None),
            1 => Ok(candidates.pop()),
            count => {
                let details = candidates
                    .iter()
                    .map(|(module_path, plan)| {
                        let declaration = plan
                            .declaration
                            .map(|die| format!(" cu={} die=0x{:x}", die.cu.0, die.offset))
                            .unwrap_or_default();
                        format!("{}{}", module_path.display(), declaration)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(anyhow::anyhow!(
                    "Ambiguous global '{base}': {count} matches [{details}]"
                ))
            }
        }
    }

    pub(super) fn select_global_plan_with_preferred_module(
        base: &str,
        prefer_module: &Path,
        candidates: Vec<(PathBuf, VariableReadPlan)>,
    ) -> Result<Option<(PathBuf, VariableReadPlan)>> {
        let (preferred, fallback): (Vec<_>, Vec<_>) = candidates
            .into_iter()
            .partition(|(module_path, _)| module_path == prefer_module);
        if !preferred.is_empty() {
            return Self::select_unambiguous_global_plan(base, preferred);
        }

        Self::select_unambiguous_global_plan(base, fallback)
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

    /// Plan a global/static member chain as a neutral read plan.
    pub fn plan_global_chain_access_read_plan(
        &self,
        prefer_module: &PathBuf,
        base: &str,
        fields: &[String],
    ) -> Result<Option<(PathBuf, VariableReadPlan)>> {
        self.plan_global_access_read_plan(
            prefer_module,
            base,
            &VariableAccessPath::fields(fields.iter().cloned()),
        )
    }

    /// Plan a global/static source-level access path as a neutral read plan.
    pub fn plan_global_access_read_plan(
        &self,
        prefer_module: &PathBuf,
        base: &str,
        path: &VariableAccessPath,
    ) -> Result<Option<(PathBuf, VariableReadPlan)>> {
        let matches = self.find_global_variables_by_name(base);
        if matches.is_empty() {
            return Ok(None);
        }

        let mut ordered: Vec<(PathBuf, GlobalVariableInfo)> = Vec::new();
        for (module_path, info) in matches.iter() {
            if *module_path == *prefer_module {
                ordered.push((module_path.clone(), info.clone()));
            }
        }
        for (module_path, info) in matches.into_iter() {
            if module_path != *prefer_module {
                ordered.push((module_path, info));
            }
        }

        let mut direct_matches = Vec::new();
        let mut last_error = None;
        for (module_path, info) in ordered {
            let base_plan = match self.resolve_variable_read_plan_by_offsets_in_module(
                &module_path,
                info.unit_offset,
                info.die_offset,
                Provenance::Synthesized {
                    detail: "global access".to_string(),
                },
            ) {
                Ok(plan) => plan,
                Err(err) => {
                    last_error = Some(err);
                    continue;
                }
            };

            match self.plan_access_path_with_type_completion(&module_path, base_plan, path) {
                Ok(plan) => direct_matches.push((module_path, plan)),
                Err(primary_error) => {
                    if Self::is_value_backed_aggregate_access_error(&primary_error) {
                        return Err(primary_error);
                    }
                    last_error = Some(primary_error);
                }
            }
        }

        if !direct_matches.is_empty() {
            return Self::select_global_plan_with_preferred_module(
                base,
                prefer_module,
                direct_matches,
            );
        }

        if let Some(err) = last_error {
            return Err(err);
        }
        Ok(None)
    }

    fn resolve_variable_read_plan_by_offsets_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
        provenance: Provenance,
    ) -> Result<VariableReadPlan> {
        let variable = self.resolve_variable_by_offsets_in_module(module_path, cu_off, die_off)?;
        Ok(Self::read_plan_from_variable(variable, provenance))
    }

    fn resolve_variable_by_offsets_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Result<crate::parser::VariableWithEvaluation> {
        let path_buf = module_path.as_ref().to_path_buf();
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
            if var.dwarf_type.is_none() {
                if let Some(ti) = module_data.shallow_type_for_variable_offsets(cu_off, die_off) {
                    var.type_name = ti.type_name();
                    var.dwarf_type = Some(ti);
                }
            }
            Ok(var)
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

use super::LoadedObjfile;
use crate::core::{GlobalVariableInfo, SectionType};
use object::{Object, ObjectSection};
use std::collections::HashSet;

impl LoadedObjfile {
    pub(crate) fn find_global_variables_by_name_any(&self, name: &str) -> Vec<GlobalVariableInfo> {
        let base = self.find_global_variables_by_name(name);
        if !base.is_empty() {
            return base;
        }

        let candidate_indices = self.matching_variable_candidate_indices(name);
        if candidate_indices.is_empty() {
            return Vec::new();
        }

        let obj = match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        let mut seen_offsets: HashSet<(u64, u64)> = HashSet::new();

        for idx in candidate_indices {
            if let Some(entry) = self.lightweight_index.entry(idx) {
                let key = (entry.unit_offset.0 as u64, entry.die_offset.0 as u64);
                if !seen_offsets.insert(key) {
                    continue;
                }
                let link_address = entry.representative_addr;
                let section = link_address.and_then(|addr| self.classify_section(&obj, addr));
                out.push(GlobalVariableInfo {
                    name: name.to_string(),
                    link_address,
                    section,
                    die_offset: entry.die_offset,
                    unit_offset: entry.unit_offset,
                });
            }
        }

        out
    }

    pub(crate) fn find_global_variables_by_name(&self, name: &str) -> Vec<GlobalVariableInfo> {
        let mut out = Vec::new();
        let entries = self.lightweight_index.find_variables_by_name(name);
        let mut seen_offsets: HashSet<(u64, u64)> = HashSet::new();

        let obj = match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(f) => f,
            Err(_) => {
                for e in entries {
                    let key = (e.unit_offset.0 as u64, e.die_offset.0 as u64);
                    if !seen_offsets.insert(key) {
                        continue;
                    }
                    let link_address = e.representative_addr;
                    out.push(GlobalVariableInfo {
                        name: e.name.to_string(),
                        link_address,
                        section: None,
                        die_offset: e.die_offset,
                        unit_offset: e.unit_offset,
                    });
                }
                return out;
            }
        };

        for e in entries {
            let key = (e.unit_offset.0 as u64, e.die_offset.0 as u64);
            if !seen_offsets.insert(key) {
                continue;
            }
            let link_address = e.representative_addr;
            let section = link_address.and_then(|addr| self.classify_section(&obj, addr));

            out.push(GlobalVariableInfo {
                name: e.name.to_string(),
                link_address,
                section,
                die_offset: e.die_offset,
                unit_offset: e.unit_offset,
            });
        }

        out
    }

    fn classify_section(&self, obj: &object::File<'_>, addr: u64) -> Option<SectionType> {
        for sect in obj.sections() {
            let saddr = sect.address();
            let ssize = sect.size();
            if ssize == 0 {
                continue;
            }
            if addr >= saddr && addr < saddr + ssize {
                let name = sect.name().ok().unwrap_or("");
                let stype = if name == ".text" || name.starts_with(".text.") {
                    SectionType::Text
                } else if name == ".rodata"
                    || name.starts_with(".rodata")
                    || name.starts_with(".data.rel.ro")
                {
                    SectionType::Rodata
                } else if name == ".data" || name.starts_with(".data") {
                    SectionType::Data
                } else if name == ".bss" || name.starts_with(".bss.") {
                    SectionType::Bss
                } else {
                    SectionType::Unknown
                };
                return Some(stype);
            }
        }
        None
    }

    pub(crate) fn classify_section_for_vaddr(&self, addr: u64) -> Option<SectionType> {
        match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(obj) => self.classify_section(&obj, addr),
            Err(_) => None,
        }
    }

    pub(crate) fn list_all_global_variables(&self) -> Vec<GlobalVariableInfo> {
        let mut out = Vec::new();
        let _obj = match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(f) => f,
            Err(_) => {
                return out;
            }
        };

        for name in self.lightweight_index.get_variable_names() {
            for info in self.find_global_variables_by_name(name) {
                out.push(info);
            }
        }

        out
    }
}

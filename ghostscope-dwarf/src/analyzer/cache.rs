use crate::semantics::PcContext;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

const PC_CONTEXT_CACHE_MAX_ENTRIES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PcContextCacheKey {
    module_path: PathBuf,
    address: u64,
}

#[derive(Debug)]
pub(super) struct PcContextCache {
    entries: HashMap<PathBuf, HashMap<u64, PcContext>>,
    insertion_order: VecDeque<PcContextCacheKey>,
    len: usize,
    max_entries: usize,
}

impl Default for PcContextCache {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            len: 0,
            max_entries: PC_CONTEXT_CACHE_MAX_ENTRIES,
        }
    }
}

impl PcContextCache {
    pub(super) fn get(&self, module_path: &Path, address: u64) -> Option<PcContext> {
        self.entries
            .get(module_path)
            .and_then(|entries| entries.get(&address))
            .cloned()
    }

    pub(super) fn insert(&mut self, module_path: PathBuf, address: u64, context: PcContext) {
        if self.max_entries == 0 {
            return;
        }

        let key = PcContextCacheKey {
            module_path,
            address,
        };
        let module_entries = self.entries.entry(key.module_path.clone()).or_default();
        if module_entries.insert(address, context).is_none() {
            self.insertion_order.push_back(key.clone());
            self.len += 1;
        }

        while self.len > self.max_entries {
            let Some(expired) = self.insertion_order.pop_front() else {
                break;
            };
            if let Some(module_entries) = self.entries.get_mut(&expired.module_path) {
                if module_entries.remove(&expired.address).is_some() {
                    self.len -= 1;
                }
                if module_entries.is_empty() {
                    self.entries.remove(&expired.module_path);
                }
            }
        }
    }
}

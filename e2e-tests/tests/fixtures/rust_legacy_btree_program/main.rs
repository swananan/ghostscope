use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::Duration;

static mut RESULT: usize = 0;

#[no_mangle]
#[inline(never)]
pub fn observe_legacy_btree_nodes(map: BTreeMap<i32, u16>, set: BTreeSet<i32>) -> usize {
    map.len() + set.len()
}

#[no_mangle]
#[inline(never)]
pub fn observe_legacy_btree_edge_cases(
    empty_map: BTreeMap<i32, u16>,
    empty_set: BTreeSet<i32>,
    unit_map: BTreeMap<(), ()>,
    unit_set: BTreeSet<()>,
) -> usize {
    empty_map.len() + empty_set.len() + unit_map.len() + unit_set.len()
}

fn main() {
    loop {
        let mut map = BTreeMap::new();
        let mut set = BTreeSet::new();
        for key in 0_i32..20 {
            map.insert(key, (key * 3 + 1) as u16);
            set.insert(key);
        }

        let mut unit_map = BTreeMap::new();
        unit_map.insert((), ());
        let mut unit_set = BTreeSet::new();
        unit_set.insert(());

        let result = observe_legacy_btree_nodes(map, set)
            + observe_legacy_btree_edge_cases(BTreeMap::new(), BTreeSet::new(), unit_map, unit_set);
        unsafe {
            std::ptr::write_volatile(&mut RESULT, result);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

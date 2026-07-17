use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::Duration;

static mut RESULT: usize = 0;

#[no_mangle]
#[inline(never)]
pub fn observe_legacy_hash_collections(
    map: HashMap<i32, u16>,
    set: HashSet<i32>,
    empty_map: HashMap<i32, u16>,
    empty_set: HashSet<i32>,
    unit_map: HashMap<(), ()>,
    unit_set: HashSet<()>,
) -> usize {
    map.len()
        + set.len()
        + empty_map.len()
        + empty_set.len()
        + unit_map.len()
        + unit_set.len()
}

fn main() {
    loop {
        let mut map = HashMap::new();
        map.insert(-7, 13);
        map.insert(29, 17);

        let mut set = HashSet::new();
        set.insert(-9);
        set.insert(5);

        let mut unit_map = HashMap::new();
        unit_map.insert((), ());
        let mut unit_set = HashSet::new();
        unit_set.insert(());

        let result = observe_legacy_hash_collections(
            map,
            set,
            HashMap::new(),
            HashSet::new(),
            unit_map,
            unit_set,
        );
        unsafe {
            std::ptr::write_volatile(&mut RESULT, result);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

static RESULT: AtomicUsize = AtomicUsize::new(0);

// This fixture intentionally uses only APIs available in Rust 1.35. The
// parameters represent the layout families most likely to change between
// target compilers; the complete adapter matrix lives in ghostscope-dwarf.
#[no_mangle]
#[inline(never)]
pub fn observe_matrix_values(
    string: String,
    vector: Vec<i32>,
    btree_map: BTreeMap<i32, u16>,
    hash_map: HashMap<i32, u16>,
) -> usize {
    string.len() + vector.len() + btree_map.len() + hash_map.len()
}

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_rc(rc: Rc<i32>) -> usize {
    *rc as usize
}

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_dst(rc: Rc<str>, arc: Arc<str>) -> usize {
    rc.len() + arc.len()
}

fn main() {
    loop {
        let mut btree_map = BTreeMap::new();
        btree_map.insert(-7, 13);

        let mut hash_map = HashMap::new();
        hash_map.insert(29, 17);

        let mut result = observe_matrix_values(
            String::from("matrix = string"),
            vec![10, -20],
            btree_map,
            hash_map,
        );
        result += observe_matrix_rc(Rc::new(11));
        result += observe_matrix_dst(Rc::from("matrix-rc"), Arc::from("matrix-arc"));
        RESULT.store(result, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(25));
    }
}

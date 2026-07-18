#![allow(dead_code)]

use std::cell::{Cell, Ref, RefCell, RefMut};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::num::NonZeroI32;
use std::rc::Rc;
use std::sync::Arc;

pub enum CompatEnum {
    Tuple(i32),
    Struct { value: i32 },
}

#[inline(never)]
pub fn observe_values(
    string: String,
    os_string: OsString,
    text: &str,
    boxed_text: Box<str>,
    slice: &[i32],
    vector: Vec<i32>,
    deque: VecDeque<i32>,
    btree_map: BTreeMap<i32, u16>,
    btree_set: BTreeSet<i32>,
    hash_map: HashMap<i32, u16>,
    hash_set: HashSet<i32>,
    rc: Rc<i32>,
    rc_text: Rc<str>,
    arc: Arc<i32>,
    arc_text: Arc<str>,
    cell: Cell<i32>,
    ref_cell: RefCell<i32>,
    nonzero: NonZeroI32,
    enum_value: CompatEnum,
) -> usize {
    let enum_value = match enum_value {
        CompatEnum::Tuple(value) => value,
        CompatEnum::Struct { value } => value,
    };
    string.len()
        + os_string.len()
        + text.len()
        + boxed_text.len()
        + slice.len()
        + vector.len()
        + deque.len()
        + btree_map.len()
        + btree_set.len()
        + hash_map.len()
        + hash_set.len()
        + *rc as usize
        + rc_text.len()
        + *arc as usize
        + arc_text.len()
        + cell.get() as usize
        + *ref_cell.borrow() as usize
        + nonzero.get() as usize
        + enum_value as usize
}

#[inline(never)]
pub fn observe_ref(value: Ref<'_, i32>) -> i32 {
    *value
}

#[inline(never)]
pub fn observe_ref_mut(mut value: RefMut<'_, i32>) -> i32 {
    *value += 1;
    *value
}

fn main() {
    let mut deque = VecDeque::new();
    deque.push_back(5);

    let mut btree_map = BTreeMap::new();
    btree_map.insert(7, 11);
    let mut btree_set = BTreeSet::new();
    btree_set.insert(13);

    let mut hash_map = HashMap::new();
    hash_map.insert(17, 19);
    let mut hash_set = HashSet::new();
    hash_set.insert(23);

    let slice = [29, 31];
    let value = observe_values(
        String::from("string"),
        OsString::from("os-string"),
        "text",
        String::from("boxed-text").into_boxed_str(),
        &slice,
        vec![3],
        deque,
        btree_map,
        btree_set,
        hash_map,
        hash_set,
        Rc::new(37),
        Rc::from("rc-text"),
        Arc::new(41),
        Arc::from("arc-text"),
        Cell::new(43),
        RefCell::new(47),
        NonZeroI32::new(53).unwrap(),
        CompatEnum::Struct { value: 59 },
    );

    let guarded = RefCell::new(61);
    let shared = observe_ref(guarded.borrow());
    let exclusive = observe_ref_mut(guarded.borrow_mut());
    println!("{}", value + shared as usize + exclusive as usize);
}

#![allow(dead_code)]

use std::cell::{Cell, Ref, RefCell, RefMut};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::num::NonZeroI32;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

pub enum CompatEnum {
    Unit,
    Tuple(i16, u16),
    Struct { left: i16, right: u16 },
}

pub enum CompatInner {
    Pair(i16, u16),
}

pub enum CompatOuter {
    Empty,
    Wrapped(CompatInner),
}

#[repr(C)]
pub enum CompatReprC {
    Unit,
    Tuple(i16, u16),
    Struct { left: i16, right: u16 },
}

pub enum CompatFieldless {
    First,
    Second,
}

pub enum CompatSingle {
    Only(i32),
}

#[repr(i8)]
pub enum CompatSigned {
    Negative = -1,
    Positive = 1,
}

#[repr(u64)]
pub enum CompatUnsigned {
    Low = 1,
    High = 0x8000_0000_0000_0000,
}

#[inline(never)]
pub fn observe_values(
    string: String,
    os_string: OsString,
    path: &Path,
    path_buf: PathBuf,
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
    fieldless: CompatFieldless,
    single: CompatSingle,
    signed: CompatSigned,
    unsigned: CompatUnsigned,
    option_nonzero: Option<NonZeroI32>,
) -> usize {
    let enum_value = match enum_value {
        CompatEnum::Unit => 0,
        CompatEnum::Tuple(left, right) => i32::from(left) + i32::from(right),
        CompatEnum::Struct { left, right } => i32::from(left) + i32::from(right),
    };
    let fieldless = match fieldless {
        CompatFieldless::First => 0,
        CompatFieldless::Second => 1,
    };
    let single = match single {
        CompatSingle::Only(value) => value,
    };
    let signed = match signed {
        CompatSigned::Negative => 1,
        CompatSigned::Positive => 0,
    };
    let unsigned = match unsigned {
        CompatUnsigned::Low => 0,
        CompatUnsigned::High => 1,
    };
    string.len()
        + os_string.len()
        + path.as_os_str().len()
        + path_buf.as_os_str().len()
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
        + fieldless
        + single as usize
        + signed
        + unsigned
        + option_nonzero.map_or(0, NonZeroI32::get) as usize
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

#[inline(never)]
pub fn observe_mut_str(value: &mut str) -> usize {
    value.len()
}

// Keep these enum-shaped parameters by value. Rust 1.35 emits only a
// declaration DIE for some reference targets, while the runtime matrix
// separately exercises the real reference and dereference path.
#[inline(never)]
pub fn observe_nested_enum(value: CompatOuter) -> usize {
    match value {
        CompatOuter::Empty => 0,
        CompatOuter::Wrapped(CompatInner::Pair(left, right)) => {
            left as usize + right as usize
        }
    }
}

#[inline(never)]
pub fn observe_pointer_niche(some: Option<&i32>, none: Option<&i32>) -> usize {
    let some = match some {
        Some(value) => *value as usize,
        None => 0,
    };
    let none = match none {
        Some(value) => *value as usize,
        None => 0,
    };
    some + none
}

#[inline(never)]
pub fn observe_repr_c_enum(
    unit: CompatReprC,
    tuple: CompatReprC,
    struct_value: CompatReprC,
) -> usize {
    let unit = match unit {
        CompatReprC::Unit => 1,
        _ => 0,
    };
    let tuple = match tuple {
        CompatReprC::Tuple(left, right) => left as usize + right as usize,
        _ => 0,
    };
    let struct_value = match struct_value {
        CompatReprC::Struct { left, right } => left as usize + right as usize,
        _ => 0,
    };
    unit + tuple + struct_value
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
    let path = PathBuf::from("borrowed/path");
    let value = observe_values(
        String::from("string"),
        OsString::from("os-string"),
        path.as_path(),
        PathBuf::from("owned/path"),
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
        CompatEnum::Struct {
            left: 59,
            right: 61,
        },
        CompatFieldless::Second,
        CompatSingle::Only(71),
        CompatSigned::Negative,
        CompatUnsigned::High,
        NonZeroI32::new(61),
    );

    let mut mutable_text = String::from("mutable-text");
    let mutable_text_len = observe_mut_str(mutable_text.as_mut_str());
    let nested = observe_nested_enum(CompatOuter::Wrapped(CompatInner::Pair(7, 9)));

    let pointed = 67;
    let pointer_some = Some(&pointed);
    let pointer_none: Option<&i32> = None;
    let pointer_niche = observe_pointer_niche(pointer_some, pointer_none);
    let repr_c = observe_repr_c_enum(
        CompatReprC::Unit,
        CompatReprC::Tuple(73, 79),
        CompatReprC::Struct {
            left: 83,
            right: 89,
        },
    );

    let guarded = RefCell::new(97);
    let shared = observe_ref(guarded.borrow());
    let exclusive = observe_ref_mut(guarded.borrow_mut());
    println!(
        "{}",
        value
            + mutable_text_len
            + nested
            + pointer_niche
            + repr_c
            + shared as usize
            + exclusive as usize
    );
}

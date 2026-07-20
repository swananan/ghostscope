use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroI32;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

static RESULT: AtomicUsize = AtomicUsize::new(0);

pub enum MatrixEnum {
    Unit,
    Tuple(i16, u16),
    Struct { value: u16, flag: u16 },
}

pub enum MatrixInner {
    Pair(i16, u16),
}

pub enum MatrixOuter {
    Empty,
    Wrapped(MatrixInner),
}

#[repr(C)]
pub enum MatrixReprC {
    Unit,
    Tuple(i16, u16),
    Struct { left: i16, right: u16 },
}

pub enum MatrixFieldless {
    First,
    Second,
}

pub enum MatrixSingle {
    Only(i32),
}

#[repr(i8)]
pub enum MatrixSigned {
    Negative = -1,
    Positive = 1,
}

#[repr(u64)]
pub enum MatrixUnsigned {
    Low = 1,
    High = 0x8000_0000_0000_0000,
}

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

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_mut_str(value: &mut str) -> usize {
    value.len()
}

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_enums(
    unit: &MatrixEnum,
    tuple: &MatrixEnum,
    struct_value: &MatrixEnum,
    fieldless: &MatrixFieldless,
    some: &Option<NonZeroI32>,
    none: &Option<NonZeroI32>,
) -> usize {
    let unit = match *unit {
        MatrixEnum::Unit => 1,
        _ => 0,
    };
    let tuple = match *tuple {
        MatrixEnum::Tuple(left, right) => left as usize + right as usize,
        _ => 0,
    };
    let struct_value = match *struct_value {
        MatrixEnum::Struct { value, flag } => value as usize + flag as usize,
        _ => 0,
    };
    let fieldless = match *fieldless {
        MatrixFieldless::First => 0,
        MatrixFieldless::Second => 1,
    };
    unit + tuple + struct_value + fieldless + some.map_or(0, NonZeroI32::get) as usize
        + none.map_or(0, NonZeroI32::get) as usize
}

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_enum_edges(
    single: &MatrixSingle,
    signed: &MatrixSigned,
    unsigned: &MatrixUnsigned,
) -> usize {
    let single = match *single {
        MatrixSingle::Only(value) => value as usize,
    };
    let signed = match *signed {
        MatrixSigned::Negative => 1,
        MatrixSigned::Positive => 0,
    };
    let unsigned = match *unsigned {
        MatrixUnsigned::Low => 0,
        MatrixUnsigned::High => 1,
    };
    single + signed + unsigned
}

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_nested(value: &MatrixOuter) -> usize {
    match value {
        MatrixOuter::Empty => 0,
        MatrixOuter::Wrapped(MatrixInner::Pair(left, right)) => {
            *left as usize + *right as usize
        }
    }
}

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_pointer_niche(
    some: &Option<&i32>,
    none: &Option<&i32>,
) -> usize {
    let some = match *some {
        Some(value) => *value as usize,
        None => 0,
    };
    let none = match *none {
        Some(value) => *value as usize,
        None => 0,
    };
    some + none
}

#[no_mangle]
#[inline(never)]
pub fn observe_matrix_repr_c(
    unit: &MatrixReprC,
    tuple: &MatrixReprC,
    struct_value: &MatrixReprC,
) -> usize {
    let unit = match unit {
        MatrixReprC::Unit => 1,
        _ => 0,
    };
    let tuple = match tuple {
        MatrixReprC::Tuple(left, right) => *left as usize + *right as usize,
        _ => 0,
    };
    let struct_value = match struct_value {
        MatrixReprC::Struct { left, right } => *left as usize + *right as usize,
        _ => 0,
    };
    unit + tuple + struct_value
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
        let mut mutable_text = String::from("matrix mutable");
        result += observe_matrix_mut_str(mutable_text.as_mut_str());
        result += observe_matrix_enums(
            &MatrixEnum::Unit,
            &MatrixEnum::Tuple(31, 37),
            &MatrixEnum::Struct {
                value: 47,
                flag: 53,
            },
            &MatrixFieldless::Second,
            &NonZeroI32::new(59),
            &None,
        );
        result += observe_matrix_enum_edges(
            &MatrixSingle::Only(71),
            &MatrixSigned::Negative,
            &MatrixUnsigned::High,
        );
        result += observe_matrix_nested(&MatrixOuter::Wrapped(MatrixInner::Pair(7, 9)));

        let pointed = 67;
        let pointer_some = Some(&pointed);
        let pointer_none: Option<&i32> = None;
        result += observe_matrix_pointer_niche(&pointer_some, &pointer_none);
        result += observe_matrix_repr_c(
            &MatrixReprC::Unit,
            &MatrixReprC::Tuple(73, 79),
            &MatrixReprC::Struct {
                left: 83,
                right: 89,
            },
        );
        RESULT.store(result, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(25));
    }
}

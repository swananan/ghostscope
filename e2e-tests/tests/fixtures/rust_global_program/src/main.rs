#![allow(non_upper_case_globals)]
#![allow(static_mut_refs)]

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    ffi::{CString, OsString},
    marker::{PhantomData, PhantomPinned},
    num::{NonZeroI32, NonZeroU128, NonZeroU32},
    rc::Rc,
    sync::Arc,
    thread,
    time::Duration,
};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

pub static mut G_COUNTER: i32 = 0;
pub static G_MESSAGE: &str = "hello from rust";
pub static G_EMPTY_MESSAGE: &str = "";
pub static G_NUL_MESSAGE: &str = "left\0right";
pub static mut G_OWNED_MESSAGE: String = String::new();
pub static mut G_EMPTY_OWNED: String = String::new();
pub static mut G_NUL_OWNED: String = String::new();
pub static mut G_SEPARATOR_OWNED: String = String::new();
pub static mut G_VEC_U8: Vec<u8> = Vec::new();
pub static mut G_VEC_I32: Vec<i32> = Vec::new();
pub static mut G_VEC_STRING: Vec<String> = Vec::new();
pub static mut G_VEC_C_STRING: Vec<CString> = Vec::new();
pub static mut G_VEC_VEC_I32: Vec<Vec<i32>> = Vec::new();
pub static mut G_VEC_VEC_STRING: Vec<Vec<String>> = Vec::new();
pub static mut G_EMPTY_VEC: Vec<i32> = Vec::new();
pub static mut G_VEC_UNIT: Vec<()> = Vec::new();
pub static mut G_VEC_DEQUE_I32: VecDeque<i32> = VecDeque::new();
pub static mut G_VEC_DEQUE_STRING: VecDeque<String> = VecDeque::new();
pub static mut G_VEC_DEQUE_UNIT: VecDeque<()> = VecDeque::new();
pub static mut G_SLICE_I32: &[i32] = &[];
pub static mut G_SLICE_STRING: &[String] = &[];
pub static mut G_MUT_SLICE_U16: &mut [u16] = &mut [];
pub static mut G_EMPTY_SLICE: &[i32] = &[];
pub static mut G_COW_STR_BORROWED: Cow<'static, str> = Cow::Borrowed("");
pub static mut G_COW_STR_OWNED: Cow<'static, str> = Cow::Borrowed("");
pub static G_NONZERO_U32: NonZeroU32 = NonZeroU32::new(7).unwrap();
pub static G_NONZERO_I32: NonZeroI32 = NonZeroI32::new(-9).unwrap();
pub static G_NONZERO_U128: NonZeroU128 =
    NonZeroU128::new(340_282_366_920_938_463_463_374_607_431_768_211_454).unwrap();
pub static mut G_CELL_U32: Cell<u32> = Cell::new(41);
pub static mut G_CELL_PAIR: Cell<(i32, u16)> = Cell::new((-4, 12));
pub static mut G_CELL_STRING: Cell<String> = Cell::new(String::new());
pub static mut G_CELL_UNIT: Cell<()> = Cell::new(());
pub static mut G_REF_CELL_IDLE: RefCell<i32> = RefCell::new(17);
pub static mut G_REF_CELL_SHARED: RefCell<i32> = RefCell::new(23);
pub static mut G_REF_CELL_MUT: RefCell<i32> = RefCell::new(31);
pub static mut G_REF_CELL_PAIR: RefCell<(i32, u16)> = RefCell::new((-6, 14));
pub static mut G_REF_CELL_STRING: RefCell<String> = RefCell::new(String::new());
pub static mut G_REF_CELL_UNIT: RefCell<()> = RefCell::new(());

pub mod user_types {
    pub struct String {
        pub vec: std::vec::Vec<u8>,
        pub marker: u32,
    }

    #[repr(C)]
    pub struct Vec<T> {
        pub buf: Buffer<T>,
        pub len: usize,
    }

    #[repr(C)]
    pub struct Buffer<T> {
        pub inner: BufferInner<T>,
    }

    #[repr(C)]
    pub struct BufferInner<T> {
        pub padding: usize,
        pub ptr: Unique<T>,
    }

    #[repr(C)]
    pub struct Unique<T> {
        pub pointer: NonNull<T>,
    }

    #[repr(C)]
    pub struct NonNull<T> {
        pub pointer: *mut T,
    }

    pub struct NonZero<T>(pub NonZeroInner<T>);

    pub struct NonZeroInner<T>(pub T);

    pub struct Cell<T>(pub UnsafeCell<T>);

    pub struct UnsafeCell<T>(pub T);

    pub struct RefCell<T> {
        pub value: UnsafeCell<T>,
        pub borrow: Cell<isize>,
    }

    pub struct BorrowRef {
        pub borrow: *const Cell<isize>,
    }

    pub struct BorrowRefMut {
        pub borrow: *const Cell<isize>,
    }

    pub struct Ref<T> {
        pub value: NonNull<T>,
        pub borrow: BorrowRef,
    }

    pub struct RefMut<T> {
        pub value: NonNull<T>,
        pub borrow: BorrowRefMut,
        pub marker: std::marker::PhantomData<T>,
    }

    pub struct Rc<T> {
        pub value: T,
    }

    pub struct Arc<T> {
        pub value: T,
    }

    pub struct HashMap<K, V> {
        pub key: K,
        pub value: V,
    }

    pub struct HashSet<T> {
        pub value: T,
    }

    pub struct BTreeMap<K, V> {
        pub key: K,
        pub value: V,
    }

    pub struct BTreeSet<T> {
        pub value: T,
    }
}

pub static mut G_USER_STRING: user_types::String = user_types::String {
    vec: Vec::new(),
    marker: 41,
};

pub static mut G_USER_VEC: user_types::Vec<i32> = user_types::Vec {
    buf: user_types::Buffer {
        inner: user_types::BufferInner {
            padding: 0,
            ptr: user_types::Unique {
                pointer: user_types::NonNull {
                    pointer: std::ptr::null_mut(),
                },
            },
        },
    },
    len: 0,
};

pub static G_USER_NONZERO: user_types::NonZero<u32> =
    user_types::NonZero(user_types::NonZeroInner(11));

pub static mut G_USER_CELL: user_types::Cell<u32> =
    user_types::Cell(user_types::UnsafeCell(13));

pub static mut G_USER_REF_CELL: user_types::RefCell<u32> = user_types::RefCell {
    value: user_types::UnsafeCell(19),
    borrow: user_types::Cell(user_types::UnsafeCell(0)),
};

#[repr(C)]
pub struct Config {
    pub a: i32,
    pub b: i64,
}

pub static mut CONFIG: Config = Config { a: 7, b: 11 };

pub struct AggregateRecord {
    pub title: String,
    pub count: i32,
}

pub static mut G_AGGREGATE_RECORD: AggregateRecord = AggregateRecord {
    title: String::new(),
    count: 0,
};
pub static mut G_VEC_AGGREGATE_RECORDS: Vec<AggregateRecord> = Vec::new();

pub struct AggregateOuter {
    pub inner: AggregateRecord,
    pub active: bool,
}

pub static mut G_AGGREGATE_OUTER: AggregateOuter = AggregateOuter {
    inner: AggregateRecord {
        title: String::new(),
        count: 0,
    },
    active: false,
};

pub struct AggregateTuple(pub String, pub i16);

pub static mut G_AGGREGATE_TUPLE: AggregateTuple = AggregateTuple(String::new(), 0);

pub struct AggregateEnvelope<T> {
    pub value: T,
    pub id: u32,
}

pub static mut G_AGGREGATE_ENVELOPE: AggregateEnvelope<String> = AggregateEnvelope {
    value: String::new(),
    id: 0,
};

#[repr(C)]
pub struct AggregateReprC {
    pub title: String,
    pub code: u16,
}

pub static mut G_AGGREGATE_REPR_C: AggregateReprC = AggregateReprC {
    title: String::new(),
    code: 0,
};

pub static mut G_OPTION_STRING: Option<String> = None;
pub static mut G_OPTION_STRING_NONE: Option<String> = None;
pub static mut G_OPTION_VEC_STRING: Option<Vec<String>> = None;
pub static mut G_RESULT_RECORD_OK: Result<AggregateRecord, String> = Err(String::new());
pub static mut G_RESULT_RECORD_ERR: Result<AggregateRecord, String> = Err(String::new());
pub static mut G_RESULT_RECORDS_OK: Result<Vec<AggregateRecord>, String> = Err(String::new());

pub enum ManyStringVariants {
    V00(String),
    V01(String),
    V02(String),
    V03(String),
    V04(String),
    V05(String),
    V06(String),
    V07(String),
    V08(String),
    V09(String),
    V10(String),
    V11(String),
    V12(String),
    V13(String),
    V14(String),
    V15(String),
}

pub static mut G_MANY_STRING_VARIANT: ManyStringVariants =
    ManyStringVariants::V00(String::new());

pub struct Pair(pub i32, pub i32);

pub struct PhantomWrapper<T> {
    pub value: i32,
    _marker: PhantomData<T>,
}

pub union NumberUnion {
    pub int_value: i32,
    pub float_value: f32,
}

#[derive(Clone, Copy)]
pub enum GlobalState {
    Idle,
    Counter(i32),
    Slice(&'static [u8]),
    TupleState { left: i32, right: bool },
}

pub trait Greeter {
    fn greet(&self) -> &'static str;
}

pub struct StaticGreeter;

impl Greeter for StaticGreeter {
    fn greet(&self) -> &'static str {
        "static-greeter"
    }
}

pub struct DynHolder<'a> {
    pub greet: Option<&'a dyn Greeter>,
}

impl<'a> DynHolder<'a> {
    fn toggle(&mut self) {
        if self.greet.is_some() {
            self.greet = None;
        } else {
            self.greet = Some(&STATIC_GREETER);
        }
    }
}

pub struct PinnedCounter {
    pub value: i32,
    _pin: PhantomPinned,
}

impl PinnedCounter {
    const fn new(value: i32) -> Self {
        Self {
            value,
            _pin: PhantomPinned,
        }
    }

    fn bump(&mut self) -> i32 {
        self.value += 1;
        self.value
    }
}

static STATIC_GREETER: StaticGreeter = StaticGreeter;
static DATA_ALPHA: &[u8] = b"alpha";
static DATA_OMEGA: &[u8] = b"omega";
static DATA_STRINGS: [&[u8]; 2] = [DATA_ALPHA, DATA_OMEGA];

pub static mut GLOBAL_TUPLE: (i32, bool) = (1, true);
pub static mut GLOBAL_PAIR: Pair = Pair(2, 3);
pub static GLOBAL_PAIRS: [Pair; 2] = [Pair(5, 8), Pair(13, 21)];
pub static mut GLOBAL_UNION: NumberUnion = NumberUnion { int_value: 10 };
pub static mut GLOBAL_SLICE: &'static [u8] = DATA_ALPHA;
pub static mut GLOBAL_NICHE: Option<NonZeroU32> = NonZeroU32::new(7);
pub static mut GLOBAL_PHANTOM: PhantomWrapper<&'static str> = PhantomWrapper {
    value: 0,
    _marker: PhantomData,
};
pub static mut GLOBAL_DYN: DynHolder<'static> = DynHolder { greet: None };
pub static mut GLOBAL_PINNED: PinnedCounter = PinnedCounter::new(0);
pub static mut GLOBAL_ENUM: GlobalState = GlobalState::Idle;
/// Mirror of GLOBAL_ENUM, kept as plain i32 so tests can assert DWARF global resolution
/// without relying on enum pretty printing.
pub static mut GLOBAL_ENUM_BITS: i32 = 0;

pub mod math {
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        ffi::{CStr, CString},
        rc::Rc,
        sync::Arc,
    };

    #[inline(never)]
    pub fn do_stuff(x: i32) -> i32 {
        // Simple function for DWARF function indexing
        x + 1
    }

    #[inline(never)]
    pub fn observe_boxed_str(value: Box<str>, empty: Box<str>) -> usize {
        value.len() + empty.len()
    }

    #[inline(never)]
    pub fn observe_box_values(
        number: Box<i32>,
        text: Box<String>,
        record: Box<crate::AggregateRecord>,
    ) -> usize {
        std::hint::black_box((
            *number,
            text.as_str(),
            record.title.as_str(),
            record.count,
        ));
        number.unsigned_abs() as usize
            + text.len()
            + record.title.len()
            + record.count.unsigned_abs() as usize
    }

    #[inline(never)]
    pub fn observe_os_string(
        value: std::ffi::OsString,
        invalid: std::ffi::OsString,
        empty: std::ffi::OsString,
    ) -> usize {
        value.len() + invalid.len() + empty.len()
    }

    #[inline(never)]
    pub fn observe_c_strings(
        owned: CString,
        borrowed: &CStr,
        empty: CString,
        invalid: CString,
        boxed: Box<CStr>,
    ) -> usize {
        owned.as_bytes().len()
            + borrowed.to_bytes().len()
            + empty.as_bytes().len()
            + invalid.as_bytes().len()
            + boxed.to_bytes().len()
    }

    #[inline(never)]
    pub fn observe_vec_deque(
        wrapped: std::collections::VecDeque<i32>,
        contiguous: std::collections::VecDeque<u16>,
        empty: std::collections::VecDeque<i32>,
    ) -> usize {
        wrapped.len() + contiguous.len() + empty.len()
    }

    #[inline(never)]
    pub fn observe_nonzero(value: std::num::NonZeroU32) -> u32 {
        value.get()
    }

    #[inline(never)]
    pub fn observe_ref_cell_states(
        idle: &std::cell::RefCell<i32>,
        shared: &std::cell::RefCell<i32>,
        mutable: &std::cell::RefCell<i32>,
        pair: &std::cell::RefCell<(i32, u16)>,
        unit: &std::cell::RefCell<()>,
        owned: std::cell::RefCell<i16>,
    ) -> usize {
        std::hint::black_box(idle.as_ptr());
        std::hint::black_box(shared.as_ptr());
        std::hint::black_box(mutable.as_ptr());
        std::hint::black_box(pair.as_ptr());
        std::hint::black_box(unit.as_ptr());
        std::hint::black_box(owned.into_inner());
        1
    }

    #[inline(never)]
    pub fn observe_ref_guards(
        shared: &std::cell::Ref<'_, i32>,
        mutable: &std::cell::RefMut<'_, i32>,
        pair: &std::cell::Ref<'_, (i32, u16)>,
        unit: &std::cell::Ref<'_, ()>,
    ) -> i64 {
        let shared = std::hint::black_box(**shared as i64);
        let mutable = std::hint::black_box(**mutable as i64);
        let pair = std::hint::black_box((**pair).0 as i64);
        std::hint::black_box(**unit);
        shared + mutable + pair
    }

    #[inline(never)]
    pub fn observe_user_ref(value: &crate::user_types::Ref<i32>) -> usize {
        std::hint::black_box(value.value.pointer);
        std::hint::black_box(value.borrow.borrow);
        1
    }

    #[inline(never)]
    pub fn observe_rc_arc(
        rc: Rc<(i32, u16)>,
        arc: Arc<(i32, u16)>,
        rc_unit: Rc<()>,
        arc_unit: Arc<()>,
    ) -> i64 {
        let rc_value = std::hint::black_box(rc.0 as i64);
        let arc_value = std::hint::black_box(arc.0 as i64);
        std::hint::black_box(Rc::strong_count(&rc));
        std::hint::black_box(Rc::weak_count(&rc));
        std::hint::black_box(Arc::strong_count(&arc));
        std::hint::black_box(Arc::weak_count(&arc));
        std::hint::black_box((rc_unit, arc_unit));
        rc_value + arc_value
    }

    #[inline(never)]
    pub fn observe_nested_owners(rc: Rc<Vec<i32>>, arc: Arc<String>) -> usize {
        std::hint::black_box((&rc, &arc));
        rc.len() + arc.len()
    }

    #[inline(never)]
    pub fn observe_user_rc_arc(
        rc: &crate::user_types::Rc<i32>,
        arc: &crate::user_types::Arc<i32>,
    ) -> i64 {
        std::hint::black_box((rc.value, arc.value));
        rc.value as i64 + arc.value as i64
    }

    #[inline(never)]
    pub fn observe_hash_collections(
        map: HashMap<i32, u16>,
        set: HashSet<i32>,
        empty_map: HashMap<i32, u16>,
        empty_set: HashSet<i32>,
        unit_map: HashMap<(), ()>,
        unit_set: HashSet<()>,
    ) -> usize {
        std::hint::black_box((
            &map,
            &set,
            &empty_map,
            &empty_set,
            &unit_map,
            &unit_set,
        ));
        map.len()
            + set.len()
            + empty_map.len()
            + empty_set.len()
            + unit_map.len()
            + unit_set.len()
    }

    #[inline(never)]
    pub fn observe_user_hash_collections(
        map: &crate::user_types::HashMap<i32, u16>,
        set: &crate::user_types::HashSet<i32>,
    ) -> i64 {
        std::hint::black_box((map.key, map.value, set.value));
        map.key as i64 + map.value as i64 + set.value as i64
    }

    #[inline(never)]
    pub fn observe_btree_collections(
        map: BTreeMap<i32, u16>,
        set: BTreeSet<i32>,
        empty_map: BTreeMap<i32, u16>,
        empty_set: BTreeSet<i32>,
        unit_map: BTreeMap<(), ()>,
        unit_set: BTreeSet<()>,
    ) -> usize {
        std::hint::black_box((
            &map,
            &set,
            &empty_map,
            &empty_set,
            &unit_map,
            &unit_set,
        ));
        map.len()
            + set.len()
            + empty_map.len()
            + empty_set.len()
            + unit_map.len()
            + unit_set.len()
    }

    #[inline(never)]
    pub fn observe_deep_btree_collections(
        map: BTreeMap<i32, u16>,
        set: BTreeSet<i32>,
    ) -> usize {
        std::hint::black_box((&map, &set));
        map.len() + set.len()
    }

    #[inline(never)]
    pub fn observe_internal_btree_collections(
        map: BTreeMap<i32, u16>,
        set: BTreeSet<i32>,
    ) -> usize {
        std::hint::black_box((&map, &set));
        map.len() + set.len()
    }

    #[inline(never)]
    pub fn observe_user_btree_collections(
        map: &crate::user_types::BTreeMap<i32, u16>,
        set: &crate::user_types::BTreeSet<i32>,
    ) -> i64 {
        std::hint::black_box((map.key, map.value, set.value));
        map.key as i64 + map.value as i64 + set.value as i64
    }
}

fn wrapped_vec_deque<T: Clone, const N: usize>(filler: T, values: [T; N]) -> VecDeque<T> {
    assert!(N > 1);
    let mut values = values.into_iter();
    let first = values.next().expect("wrapped deque values are nonempty");
    let mut deque = VecDeque::with_capacity(N);
    let filler_len = deque.capacity() - 1;

    for _ in 0..filler_len {
        deque.push_back(filler.clone());
    }
    deque.push_back(first);
    for _ in 0..filler_len {
        deque.pop_front();
    }
    deque.extend(values);

    deque
}

fn touch_globals() -> i32 {
    // SAFETY: This single-threaded fixture mutates its own static test globals to
    // keep DWARF global-variable scenarios observable.
    unsafe {
        G_COUNTER = G_COUNTER.wrapping_add(1);
        CONFIG.a = CONFIG.a.wrapping_add(1);

        GLOBAL_TUPLE.0 = GLOBAL_TUPLE.0.wrapping_add(1);
        GLOBAL_TUPLE.1 = !GLOBAL_TUPLE.1;

        GLOBAL_PAIR.0 = GLOBAL_PAIR.0.wrapping_add(GLOBAL_PAIR.1);
        GLOBAL_PAIR.1 = GLOBAL_PAIR.0.wrapping_sub(GLOBAL_PAIR.1);

        let mut union_value = GLOBAL_UNION.int_value.wrapping_add(1);
        GLOBAL_UNION.int_value = union_value;
        if union_value % 5 == 0 {
            // Flip to float representation occasionally to keep DWARF union data interesting.
            union_value = union_value.wrapping_add(1);
            GLOBAL_UNION.float_value = union_value as f32 * 1.5;
        }

        let current_slice = GLOBAL_SLICE;
        GLOBAL_SLICE = if current_slice.as_ptr() == DATA_STRINGS[0].as_ptr() {
            DATA_STRINGS[1]
        } else {
            DATA_STRINGS[0]
        };

        let nonzero_seed = GLOBAL_PAIR.0.unsigned_abs().max(1);
        GLOBAL_NICHE = NonZeroU32::new(nonzero_seed);
        GLOBAL_PHANTOM.value = GLOBAL_PHANTOM.value.wrapping_add(1);
        GLOBAL_DYN.toggle();
        let pinned_value = GLOBAL_PINNED.bump();

        let enum_snapshot = GLOBAL_ENUM;
        let next_state = match enum_snapshot {
            GlobalState::Idle => GlobalState::Counter(G_COUNTER),
            GlobalState::Counter(val) if val % 2 == 0 => GlobalState::Slice(GLOBAL_SLICE),
            GlobalState::Counter(_) => GlobalState::TupleState {
                left: GLOBAL_TUPLE.0,
                right: GLOBAL_TUPLE.1,
            },
            GlobalState::Slice(_) => GlobalState::Idle,
            GlobalState::TupleState { .. } => GlobalState::Counter(GLOBAL_PAIR.0),
        };
        GLOBAL_ENUM = next_state;
        let enum_contrib = match enum_snapshot {
            GlobalState::Idle => 0,
            GlobalState::Counter(val) => val,
            GlobalState::Slice(slice) => slice.len() as i32,
            GlobalState::TupleState { left, right } => left + if right { 1 } else { 0 },
        };
        GLOBAL_ENUM_BITS = enum_contrib;
        G_CELL_UNIT.get();

        let total = CONFIG.a as i64
            + G_MESSAGE.len() as i64
            + G_EMPTY_MESSAGE.len() as i64
            + G_NUL_MESSAGE.len() as i64
            + G_OWNED_MESSAGE.len() as i64
            + G_EMPTY_OWNED.len() as i64
            + G_NUL_OWNED.len() as i64
            + G_SEPARATOR_OWNED.len() as i64
            + G_USER_STRING.vec.len() as i64
            + G_USER_STRING.marker as i64
            + G_VEC_U8.len() as i64
            + G_VEC_I32.len() as i64
            + G_VEC_STRING.len() as i64
            + G_VEC_C_STRING.len() as i64
            + G_VEC_VEC_I32.len() as i64
            + G_VEC_VEC_STRING.len() as i64
            + G_EMPTY_VEC.len() as i64
            + G_VEC_UNIT.len() as i64
            + G_VEC_DEQUE_I32.len() as i64
            + G_VEC_DEQUE_STRING.len() as i64
            + G_VEC_DEQUE_UNIT.len() as i64
            + G_SLICE_I32.len() as i64
            + G_SLICE_STRING.len() as i64
            + G_MUT_SLICE_U16.len() as i64
            + G_EMPTY_SLICE.len() as i64
            + G_COW_STR_BORROWED.len() as i64
            + G_COW_STR_OWNED.len() as i64
            + G_NONZERO_U32.get() as i64
            + G_NONZERO_I32.get() as i64
            + G_NONZERO_U128.get() as i64
            + G_CELL_U32.get() as i64
            + G_CELL_PAIR.get().0 as i64
            + (&*G_CELL_STRING.as_ptr()).len() as i64
            + *G_REF_CELL_IDLE.get_mut() as i64
            + *G_REF_CELL_SHARED.get_mut() as i64
            + *G_REF_CELL_MUT.get_mut() as i64
            + G_REF_CELL_PAIR.get_mut().0 as i64
            + G_REF_CELL_STRING.get_mut().len() as i64
            + G_AGGREGATE_RECORD.title.len() as i64
            + G_AGGREGATE_RECORD.count as i64
            + G_VEC_AGGREGATE_RECORDS.len() as i64
            + G_AGGREGATE_OUTER.inner.title.len() as i64
            + G_AGGREGATE_OUTER.inner.count as i64
            + G_AGGREGATE_TUPLE.0.len() as i64
            + G_AGGREGATE_ENVELOPE.value.len() as i64
            + G_AGGREGATE_REPR_C.title.len() as i64
            + G_OPTION_STRING.as_ref().map(String::len).unwrap_or(0) as i64
            + G_OPTION_STRING_NONE
                .as_ref()
                .map(String::len)
                .unwrap_or(0) as i64
            + G_OPTION_VEC_STRING
                .as_ref()
                .map(Vec::len)
                .unwrap_or(0) as i64
            + match &G_RESULT_RECORD_OK {
                Ok(record) => record.title.len() as i64 + record.count as i64,
                Err(error) => error.len() as i64,
            }
            + match &G_RESULT_RECORD_ERR {
                Ok(record) => record.title.len() as i64 + record.count as i64,
                Err(error) => error.len() as i64,
            }
            + match &G_RESULT_RECORDS_OK {
                Ok(records) => records
                    .iter()
                    .map(|record| record.title.len() as i64 + record.count as i64)
                    .sum(),
                Err(error) => error.len() as i64,
            }
            + match &G_MANY_STRING_VARIANT {
                ManyStringVariants::V00(value)
                | ManyStringVariants::V01(value)
                | ManyStringVariants::V02(value)
                | ManyStringVariants::V03(value)
                | ManyStringVariants::V04(value)
                | ManyStringVariants::V05(value)
                | ManyStringVariants::V06(value)
                | ManyStringVariants::V07(value)
                | ManyStringVariants::V08(value)
                | ManyStringVariants::V09(value)
                | ManyStringVariants::V10(value)
                | ManyStringVariants::V11(value)
                | ManyStringVariants::V12(value)
                | ManyStringVariants::V13(value)
                | ManyStringVariants::V14(value)
                | ManyStringVariants::V15(value) => value.len() as i64,
            }
            + G_USER_NONZERO.0.0 as i64
            + G_USER_CELL.0.0 as i64
            + G_USER_REF_CELL.value.0 as i64
            + G_USER_VEC.len as i64
            + GLOBAL_PAIRS[0].0 as i64
            + union_value as i64
            + pinned_value as i64
            + GLOBAL_PHANTOM.value as i64
            + enum_contrib as i64;

        total as i32
    }
}

fn main() {
    // SAFETY: The fixture initializes these globals before its tracing loop and
    // does not mutate them afterward.
    unsafe {
        G_OWNED_MESSAGE = String::from("owned from rust");
        G_NUL_OWNED = String::from("owned\0value");
        G_SEPARATOR_OWNED = String::from("left = right");
        G_USER_STRING.vec = b"user bytes".to_vec();
        G_VEC_U8 = vec![1, 2, 3, 255];
        G_VEC_I32 = vec![10, -20, 30, 40];
        G_VEC_STRING = vec![
            String::from("alpha"),
            String::from("nested rust"),
            String::from("omega"),
            String::from("delta"),
            String::from("fifth element"),
        ];
        G_VEC_C_STRING = ["alpha c", "beta c", "gamma c", "delta c", "fifth c"]
            .into_iter()
            .map(|value| CString::new(value).unwrap())
            .collect();
        G_VEC_VEC_I32 = vec![vec![1, 2], vec![3, 5, 8], vec![-13]];
        G_VEC_VEC_STRING = vec![
            vec![String::from("deep alpha")],
            vec![String::from("deep beta")],
        ];
        G_VEC_UNIT = vec![(); 3];
        G_VEC_DEQUE_I32 = VecDeque::from([10, 20, 30, 40]);
        let string_deque = wrapped_vec_deque(
            String::new(),
            [
                String::from("deque alpha"),
                String::from("deque beta"),
                String::from("deque gamma"),
            ],
        );
        assert!(!string_deque.as_slices().1.is_empty());
        G_VEC_DEQUE_STRING = string_deque;
        G_VEC_DEQUE_UNIT = VecDeque::from([(), (), ()]);
        G_SLICE_I32 = Box::leak(vec![7, -8, 9].into_boxed_slice());
        G_SLICE_STRING = Box::leak(
            vec![
                String::from("slice alpha"),
                String::from("slice beta"),
            ]
            .into_boxed_slice(),
        );
        G_MUT_SLICE_U16 = Box::leak(vec![1000, 2000, 65535].into_boxed_slice());
        G_COW_STR_BORROWED = Cow::Borrowed("borrowed cow");
        G_COW_STR_OWNED = Cow::Owned(String::from("owned cow"));
        G_CELL_STRING.set(String::from("cell nested"));
        *G_REF_CELL_STRING.get_mut() = String::from("refcell nested");
        G_AGGREGATE_RECORD = AggregateRecord {
            title: String::from("root aggregate"),
            count: 7,
        };
        G_VEC_AGGREGATE_RECORDS = vec![
            AggregateRecord {
                title: String::from("first"),
                count: 11,
            },
            AggregateRecord {
                title: String::from("second"),
                count: 13,
            },
        ];
        G_AGGREGATE_OUTER = AggregateOuter {
            inner: AggregateRecord {
                title: String::from("nested record"),
                count: 17,
            },
            active: true,
        };
        G_AGGREGATE_TUPLE = AggregateTuple(String::from("tuple aggregate"), 19);
        G_AGGREGATE_ENVELOPE = AggregateEnvelope {
            value: String::from("generic aggregate"),
            id: 23,
        };
        G_AGGREGATE_REPR_C = AggregateReprC {
            title: String::from("repr aggregate"),
            code: 29,
        };
        G_OPTION_STRING = Some(String::from("optional value"));
        G_OPTION_STRING_NONE = None;
        G_OPTION_VEC_STRING = Some(vec![
            String::from("option alpha"),
            String::from("option beta"),
        ]);
        G_RESULT_RECORD_OK = Ok(AggregateRecord {
            title: String::from("result record"),
            count: 31,
        });
        G_RESULT_RECORD_ERR = Err(String::from("result error"));
        G_RESULT_RECORDS_OK = Ok(vec![
            AggregateRecord {
                title: String::from("result one"),
                count: 37,
            },
            AggregateRecord {
                title: String::from("result two"),
                count: 41,
            },
        ]);
        G_MANY_STRING_VARIANT =
            ManyStringVariants::V07(String::from("shared variant budget"));
    }

    let mut acc: i64 = 0;
    for _ in 0..50000 {
        acc += math::do_stuff(3) as i64;
        acc += math::observe_boxed_str("boxed from rust".into(), "".into()) as i64;
        acc += math::observe_box_values(
            Box::new(-101),
            Box::new(String::from("boxed string")),
            Box::new(AggregateRecord {
                title: String::from("boxed record"),
                count: 103,
            }),
        ) as i64;
        acc += math::observe_os_string(
            OsString::from("os from rust"),
            OsString::from_vec(vec![b'o', b's', 0xff, b'x']),
            OsString::new(),
        ) as i64;
        let borrowed_c_string = CString::new("borrowed c").unwrap();
        acc += math::observe_c_strings(
            CString::new("owned c").unwrap(),
            borrowed_c_string.as_c_str(),
            CString::new("").unwrap(),
            CString::new(vec![b'c', 0xff, b'x']).unwrap(),
            CString::new("boxed c").unwrap().into_boxed_c_str(),
        ) as i64;
        acc += math::observe_vec_deque(
            wrapped_vec_deque(-1, [10, 20, 30, 40]),
            VecDeque::from([7_u16, 8, 9]),
            VecDeque::new(),
        ) as i64;
        acc += math::observe_nonzero(NonZeroU32::new(23).unwrap()) as i64;
        // SAFETY: The fixture is single-threaded. The guards deliberately stay
        // live across the probe so its borrow-state presentation is observable.
        unsafe {
            let shared_one = G_REF_CELL_SHARED.borrow();
            let shared_two = G_REF_CELL_SHARED.borrow();
            let mutable = G_REF_CELL_MUT.borrow_mut();
            acc += math::observe_ref_cell_states(
                &G_REF_CELL_IDLE,
                &G_REF_CELL_SHARED,
                &G_REF_CELL_MUT,
                &G_REF_CELL_PAIR,
                &G_REF_CELL_UNIT,
                RefCell::new(-12_i16),
            ) as i64;
            let pair = G_REF_CELL_PAIR.borrow();
            let unit = G_REF_CELL_UNIT.borrow();
            acc += math::observe_ref_guards(&shared_one, &mutable, &pair, &unit);
            acc += pair.0 as i64;
            acc += *shared_one as i64 + *shared_two as i64 + *mutable as i64;
        }
        let user_ref = user_types::Ref {
            value: user_types::NonNull {
                pointer: std::ptr::null_mut(),
            },
            borrow: user_types::BorrowRef {
                borrow: std::ptr::null(),
            },
        };
        acc += math::observe_user_ref(&user_ref) as i64;
        let rc = Rc::new((-7_i32, 13_u16));
        let rc_peer = Rc::clone(&rc);
        let rc_weak = Rc::downgrade(&rc);
        let arc = Arc::new((29_i32, 17_u16));
        let arc_peer = Arc::clone(&arc);
        let arc_weak = Arc::downgrade(&arc);
        acc += math::observe_rc_arc(
            Rc::clone(&rc),
            Arc::clone(&arc),
            Rc::new(()),
            Arc::new(()),
        );
        acc += math::observe_nested_owners(
            Rc::new(vec![3, 5, 8]),
            Arc::new(String::from("arc nested")),
        ) as i64;
        std::hint::black_box((rc_peer, rc_weak, arc_peer, arc_weak));
        let user_rc = user_types::Rc { value: 37_i32 };
        let user_arc = user_types::Arc { value: 41_i32 };
        acc += math::observe_user_rc_arc(&user_rc, &user_arc);
        let map = HashMap::from([(-7_i32, 13_u16), (29_i32, 17_u16)]);
        let set = HashSet::from([-9_i32, 5_i32]);
        acc += math::observe_hash_collections(
            map,
            set,
            HashMap::new(),
            HashSet::new(),
            HashMap::from([((), ())]),
            HashSet::from([()]),
        ) as i64;
        let user_map = user_types::HashMap {
            key: 43_i32,
            value: 47_u16,
        };
        let user_set = user_types::HashSet { value: 53_i32 };
        acc += math::observe_user_hash_collections(&user_map, &user_set);
        acc += math::observe_btree_collections(
            BTreeMap::from([(-7_i32, 13_u16), (29_i32, 17_u16)]),
            BTreeSet::from([-9_i32, 5_i32]),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::from([((), ())]),
            BTreeSet::from([()]),
        ) as i64;
        let internal_map = (0_i32..20)
            .map(|key| (key, (key * 3 + 1) as u16))
            .collect();
        let internal_set = (0_i32..20).collect();
        acc += math::observe_internal_btree_collections(internal_map, internal_set) as i64;
        let deep_map = (0_i32..160)
            .map(|key| (key, (key * 3 + 1) as u16))
            .collect();
        let deep_set = (0_i32..160).collect();
        acc += math::observe_deep_btree_collections(deep_map, deep_set) as i64;
        let user_btree_map = user_types::BTreeMap {
            key: 59_i32,
            value: 61_u16,
        };
        let user_btree_set = user_types::BTreeSet { value: 67_i32 };
        acc += math::observe_user_btree_collections(
            &user_btree_map,
            &user_btree_set,
        );
        acc += touch_globals() as i64;
        thread::sleep(Duration::from_millis(1000));
    }
    // Prevent optimization from dropping acc
    if acc == 0x7fff_ffff { println!("dead"); }
}

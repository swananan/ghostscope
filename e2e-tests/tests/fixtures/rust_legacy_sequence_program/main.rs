use std::collections::VecDeque;
use std::thread;
use std::time::Duration;

static SLICE_VALUES: [i32; 3] = [-3, 5, 8];
static EMPTY_SLICE: [i32; 0] = [];
static mut RESULT: usize = 0;

fn wrapped_vec_deque() -> VecDeque<i32> {
    let mut values = VecDeque::with_capacity(8);
    let advance = values.capacity() - 2;
    for _ in 0..advance {
        values.push_back(-1);
    }
    for _ in 0..advance {
        let _ = values.pop_front();
    }
    for value in 3_i32..=8 {
        values.push_back(value);
    }
    assert!(!values.as_slices().1.is_empty());
    values
}

#[no_mangle]
#[inline(never)]
pub fn observe_legacy_sequences(
    slice: &[i32],
    vector: Vec<i32>,
    wrapped: VecDeque<i32>,
    contiguous: VecDeque<u16>,
    empty_slice: &[i32],
    empty_vector: Vec<i32>,
    empty_deque: VecDeque<i32>,
    unit_vector: Vec<()>,
    unit_deque: VecDeque<()>,
) -> usize {
    slice.len()
        + vector.len()
        + wrapped.len()
        + contiguous.len()
        + empty_slice.len()
        + empty_vector.len()
        + empty_deque.len()
        + unit_vector.len()
        + unit_deque.len()
}

fn main() {
    loop {
        // eBPF user-memory reads are non-faulting. Touch the static slice before
        // the probe fires so this test exercises slice capture, not page residency.
        unsafe {
            std::ptr::read_volatile(SLICE_VALUES.as_ptr());
        }

        let mut contiguous = VecDeque::new();
        contiguous.push_back(7);
        contiguous.push_back(8);
        contiguous.push_back(9);

        let mut unit_deque = VecDeque::new();
        unit_deque.push_back(());
        unit_deque.push_back(());
        unit_deque.push_back(());

        let result = observe_legacy_sequences(
            &SLICE_VALUES,
            vec![10, -20, 30],
            wrapped_vec_deque(),
            contiguous,
            &EMPTY_SLICE,
            Vec::new(),
            VecDeque::new(),
            vec![(); 3],
            unit_deque,
        );
        unsafe {
            std::ptr::write_volatile(&mut RESULT, result);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

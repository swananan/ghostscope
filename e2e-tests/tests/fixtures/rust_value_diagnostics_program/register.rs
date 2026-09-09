use std::cell::Cell;

type Nested = Cell<Cell<Cell<u64>>>;

#[used]
#[no_mangle]
pub static mut G_REGISTER_PEER: Nested = Cell::new(Cell::new(Cell::new(73)));

#[inline(never)]
#[no_mangle]
pub extern "C" fn observe_register(value: Nested) -> u64 {
    // Keep a real call site: noinline alone does not stop interprocedural
    // simplification of a pure identity function.
    std::hint::black_box(value.into_inner().into_inner().into_inner())
}

fn main() {
    loop {
        // The eight-byte cells own no allocations. Keep the memory-backed peer
        // resident without changing the register-backed argument's location.
        unsafe {
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!(G_REGISTER_PEER),
                Cell::new(Cell::new(Cell::new(73))),
            );
        }
        std::hint::black_box(observe_register(Cell::new(Cell::new(Cell::new(
            std::hint::black_box(41),
        )))));
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

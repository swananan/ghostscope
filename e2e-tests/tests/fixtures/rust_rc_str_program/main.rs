use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static mut RESULT: usize = 0;

#[no_mangle]
#[inline(never)]
pub fn observe_reference_counted_str(value: Rc<str>, shared: Arc<str>) -> usize {
    std::hint::black_box((Rc::strong_count(&value), Rc::weak_count(&value)));
    std::hint::black_box((Arc::strong_count(&shared), Arc::weak_count(&shared)));
    value.len() + shared.len()
}

fn main() {
    loop {
        let value: Rc<str> = Rc::from("rust = rc");
        let peer = Rc::clone(&value);
        let weak = Rc::downgrade(&value);
        let shared: Arc<str> = Arc::from("rust = arc");
        let shared_peer = Arc::clone(&shared);
        let shared_weak = Arc::downgrade(&shared);
        let result = observe_reference_counted_str(
            Rc::clone(&value),
            Arc::clone(&shared),
        );
        std::hint::black_box((&peer, &weak, &shared_peer, &shared_weak));
        unsafe {
            std::ptr::write_volatile(&mut RESULT, result);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

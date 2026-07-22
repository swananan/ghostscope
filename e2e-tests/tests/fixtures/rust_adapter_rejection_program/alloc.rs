pub mod string {
    pub struct String;
}

#[used]
#[no_mangle]
pub static G_REJECTED_STRING: string::String = string::String;

#[inline(never)]
#[no_mangle]
pub extern "C" fn observe_adapter_rejection() -> usize {
    std::hint::black_box(&G_REJECTED_STRING as *const _ as usize)
}

fn main() {
    loop {
        std::hint::black_box(observe_adapter_rejection());
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

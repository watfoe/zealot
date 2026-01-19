#[macro_use]
extern crate afl;
use zealot::RatchetMessage;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = RatchetMessage::from_bytes(data);
    });
}

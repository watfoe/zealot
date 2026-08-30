#[macro_use]
extern crate afl;
use zealot::Session;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = Session::deserialize(data);
    });
}

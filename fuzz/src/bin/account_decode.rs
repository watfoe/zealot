#[macro_use]
extern crate afl;
use zealot::Account;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = Account::deserialize(data);
    });
}

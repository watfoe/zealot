#[macro_use]
extern crate afl;
use zealot::{Account, RatchetMessage, Session, X3DHPublicKeys};

fn get_session() -> Session {
    // The Victim
    let alice = Account::new(None);

    // The Attacker context
    let bob = Account::new(None);
    let bob_bundle = bob.prekey_bundle();
    let bob_public = X3DHPublicKeys::from(&bob_bundle);

    alice
        .create_outbound_session(&bob_public)
        .expect("Setup failed")
}

fn main() {
    let mut session = get_session();
    let associated_data = b"fuzz-context";

    fuzz!(|data: &[u8]| {
        if let Ok(msg) = RatchetMessage::from_bytes(data) {
            let _ = session.decrypt(&msg, associated_data);
        }
    });
}

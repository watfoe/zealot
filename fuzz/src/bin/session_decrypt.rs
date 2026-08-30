#[macro_use]
extern crate afl;
use zealot::{Account, RatchetMessage, Session, X3DHPublicKeys};

fn get_session() -> Session {
    let a = Account::new(None);

    let b = Account::new(None);
    let b_bundle = b.prekey_bundle();

    let b_public = X3DHPublicKeys::try_from(
        b_bundle.ik_public.to_bytes(),
        b_bundle.signing_key_public.to_bytes(),
        (b_bundle.spk_public.0, b_bundle.spk_public.1.to_bytes()),
        b_bundle.signature.to_bytes(),
        b_bundle
            .otpks_public
            .iter()
            .next()
            .map(|(id, key)| (*id, key.to_bytes())),
    )
    .expect("Setup failed");

    a.create_outbound_session(&b_public).expect("Setup failed")
}

fn main() {
    let mut session = get_session();
    fuzz!(|data: &[u8]| {
        if let Ok(msg) = RatchetMessage::from_bytes(data) {
            let _ = session.decrypt(&msg);
        }
    });
}

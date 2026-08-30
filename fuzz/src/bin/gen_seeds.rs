//! Writes valid serialized blobs into the seed directories of the deserialization
//! harnesses.
//!
//! Both harnesses decode Protocol Buffers, so a placeholder seed is rejected on the
//! first byte and leaves the fuzzer with nothing to mutate. Starting from a real
//! blob lets AFL explore the structure instead of rediscovering it.

use std::fs;
use std::path::Path;
use zealot::{Account, X3DHPublicKeys};

fn main() {
    let a_acc = Account::new(None);
    let mut b_acc = Account::new(None);

    let b_pkb = b_acc.prekey_bundle();
    let b_x3dh_keys = X3DHPublicKeys::try_from(
        b_pkb.ik_public.to_bytes(),
        b_pkb.signing_key_public.to_bytes(),
        (b_pkb.spk_public.0, b_pkb.spk_public.1.to_bytes()),
        b_pkb.signature.to_bytes(),
        b_pkb
            .otpks_public
            .iter()
            .next()
            .map(|(id, key)| (*id, key.to_bytes())),
    )
    .expect("pkb should be well formed");

    let mut a_ses = a_acc
        .create_outbound_session(&b_x3dh_keys)
        .expect("outbound session");
    let mut b_ses = b_acc
        .create_inbound_session(
            a_acc.ik_public(),
            &a_ses.x3dh_keys().expect("x3dh keys"),
        )
        .expect("inbound session");

    // Exercise both chains, and leave skipped message keys behind, so the seed
    // covers more of the session state than a freshly created session would.
    let msgs: Vec<_> = (0..5)
        .map(|i| {
            a_ses
                .encrypt(format!("seed message {i}").as_bytes())
                .expect("encrypt")
        })
        .collect();
    b_ses.decrypt(&msgs[4]).expect("decrypt");
    let reply = b_ses.encrypt(b"seed reply").expect("encrypt");
    a_ses.decrypt(&reply).expect("decrypt");

    write("in/account_decode/account.bin", &b_acc.serialize().expect("account"));
    write("in/session_decode/session.bin", &b_ses.serialize().expect("session"));
}

fn write(path: &str, bytes: &[u8]) {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create seed directory");
    }
    fs::write(path, bytes).expect("write seed");
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}
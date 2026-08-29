//! # Zealot; Signal's X3DH and Double Ratchet Protocol Implementation

fn main() -> std::io::Result<()> {
    let protos = ["src/proto/zealot.proto"];
    let mut prost_build = prost_build::Config::new();
    // Generate `BTreeMap` so `Account::serialize` is byte-for-byte reproducible.
    prost_build.btree_map(["."]);
    prost_build.compile_protos(&protos, &["src"])?;

    Ok(())
}

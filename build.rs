//! # A Signal Protocol Implementation

fn main() {
    let protos = ["src/proto/zealot.proto"];
    let mut prost_build = prost_build::Config::new();
    prost_build
        .compile_protos(&protos, &["src"])
        .expect("Protobufs in src are valid");
}

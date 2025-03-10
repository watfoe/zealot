fn main() {
    let protos = ["src/proto/account.proto"];
    let mut prost_build = prost_build::Config::new();
    prost_build
        .compile_protos(&protos, &["src"])
        .expect("Protobufs in src are valid");
}

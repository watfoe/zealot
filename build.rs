//! # A Signal Protocol Implementation

fn main() -> std::io::Result<()> {
    let protos = ["src/proto/zealot.proto"];
    let mut prost_build = prost_build::Config::new();
    prost_build.compile_protos(&protos, &["src"])?;

    Ok(())
}

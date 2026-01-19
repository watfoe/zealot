# AFL based fuzz setup for Zealot

## Setup

You will need a nightly Rust compiler for this to work effectively:

```bash
$ rustup toolchain install nightly
```

After that, `afl-rs` needs to be installed. The complete setup guide can be found [here](https://rust-fuzz.github.io/book/afl/setup.html), but you can typically install it with cargo:

```bash
$ cargo install cargo-afl
```

## Building the Harnesses

Switch to the fuzz directory and build the binaries using the `cargo afl` wrapper. This instruments the code for coverage-guided fuzzing.

```bash
$ cd fuzz
$ cargo afl build
```

## Running the Fuzzers

We currently have two primary fuzzing targets. You must ensure the input directory (`-i`) exists and contains at least one "seed" file (even a dummy one) before starting.

### Example: Message Decoding (`msg_decode`)

Fuzzes the `RatchetMessage::from_bytes` deserializer.

```bash
# 1. Create directories and seed
$mkdir -p in/msg_decode out/msg_decode$ echo "seed" > in/msg_decode/seed.txt

# 2. Run the fuzzer
$ cargo afl fuzz -i in/msg_decode -o out/msg_decode target/debug/msg_decode
```

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

We currently have four fuzzing targets. You must ensure the input directory (`-i`) exists and contains at least one "seed" file (even a dummy one) before starting.

### Example: Message Decoding (`msg_decode`)

Fuzzes the `RatchetMessage::from_bytes` deserializer.

```bash
# 1. Create directories and seed
$ mkdir -p in/msg_decode out/msg_decode
$ echo "seed" > in/msg_decode/seed.txt

# 2. Run the fuzzer
$ cargo afl fuzz -i in/msg_decode -o out/msg_decode target/debug/msg_decode
```

### Session Decryption (`session_decrypt`)

Fuzzes `Session::decrypt` against a live session.

```bash
$ mkdir -p in/session_decrypt out/session_decrypt
$ echo "seed" > in/session_decrypt/seed.txt
$ cargo afl fuzz -i in/session_decrypt -o out/session_decrypt target/debug/session_decrypt
```

### State Restoration (`account_decode`, `session_decode`)

Fuzzes `Account::deserialize` and `Session::deserialize`, the paths that read
persisted state back from storage. A panic here is a denial of service on startup,
so these targets matter even though the input is usually trusted.

Both decode Protocol Buffers, so a placeholder seed is rejected on the first byte
and leaves the fuzzer nothing to mutate. Generate real seeds first:

```bash
$ cargo run --bin gen_seeds
```

That writes a serialized account and session into `in/account_decode/` and
`in/session_decode/`. The seeds are generated rather than committed because a
serialized account carries private key material; they are listed in `.gitignore`.

```bash
$ cargo afl fuzz -i in/account_decode -o out/account_decode target/debug/account_decode
$ cargo afl fuzz -i in/session_decode -o out/session_decode target/debug/session_decode
```

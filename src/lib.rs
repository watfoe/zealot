// The crate-level documentation is the project README, so the overview, the
// feature list, and the usage example have exactly one source, and the example is
// compiled as a doctest rather than being an unchecked code block.
// `//` rather than `//!` here: this note is for maintainers and must not render
// ahead of the README in the published documentation.
#![doc = include_str!("../README.md")]

mod types;
pub use types::*;

mod x3dh;
pub use x3dh::*;

mod ratchet;
pub use ratchet::*;

mod error;
pub use error::Error;

mod account;
pub use account::*;

mod proto;
pub use proto::*;

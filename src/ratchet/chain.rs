use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single-use message key produced by a [`Chain`].
///
/// The key is wiped when the value is dropped, so a key that is used once, is
/// evicted from the skipped-key store, or belongs to a discarded copy of that
/// store never lingers in freed memory.
#[derive(Clone)]
pub(crate) struct MessageKey(Box<[u8; 32]>);

impl MessageKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<Box<[u8; 32]>> for MessageKey {
    fn from(bytes: Box<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

impl Zeroize for MessageKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MessageKey {}

/// Ratchet chain for deriving keys
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Chain {
    pub(crate) chain_key: Box<[u8; 32]>,
    pub(crate) index: u32,
}

impl Chain {
    pub(crate) fn new(chain_key: Box<[u8; 32]>) -> Self {
        Self {
            chain_key,
            index: 0,
        }
    }

    /// Advances the chain and returns a message key
    pub(crate) fn next(&mut self) -> MessageKey {
        let mut message_result = Self::hmac(&self.chain_key, 0x01);
        let mut message_key = Box::new([0u8; 32]);
        message_key.copy_from_slice(&message_result);
        message_result.zeroize();

        let mut chain_result = Self::hmac(&self.chain_key, 0x02);
        self.chain_key.copy_from_slice(&chain_result);
        chain_result.zeroize();

        self.index = self.index.wrapping_add(1);

        MessageKey(message_key)
    }

    #[expect(
        clippy::expect_used,
        reason = "HMAC accepts a key of any length, so construction cannot fail"
    )]
    fn hmac(key: &[u8; 32], input: u8) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a key of any length");
        mac.update(&[input]);
        mac.finalize().into_bytes().into()
    }

    /// Only used during hydration stage from a serialized copy
    pub(crate) fn set_index(&mut self, index: u32) {
        self.index = index;
    }
}

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    pub(crate) fn next(&mut self) -> Box<[u8; 32]> {
        type HmacSha256 = Hmac<Sha256>;

        let mut chain_mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key.as_slice())
            .expect("HMAC initialization failed");
        chain_mac.update(&[0x01]);
        let chain_result = chain_mac.finalize().into_bytes();

        let mut message_mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key.as_slice())
            .expect("HMAC initialization failed");
        message_mac.update(&[0x02]);
        let message_result = message_mac.finalize().into_bytes();

        self.chain_key.copy_from_slice(&chain_result);
        self.index = self.index.wrapping_add(1);

        let mut message_key = Box::new([0u8; 32]);
        message_key.copy_from_slice(&message_result);
        message_key
    }

    pub(crate) fn set_index(&mut self, index: u32) {
        self.index = index;
    }
}

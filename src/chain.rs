use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// Ratchet chain for deriving keys
#[derive(Clone, Default)]
pub(crate) struct Chain {
    pub(crate) chain_key: [u8; 32],
    index: u32,
}

impl Chain {
    pub(crate) fn new(chain_key: [u8; 32]) -> Self {
        Self {
            chain_key,
            index: 0,
        }
    }

    /// Advances the chain and returns a message key
    pub(crate) fn next(&mut self) -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;

        let mut chain_mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key)
            .expect("HMAC initialization failed");
        chain_mac.update(&[0x01]);
        let chain_result = chain_mac.finalize().into_bytes();

        let mut message_mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key)
            .expect("HMAC initialization failed");
        message_mac.update(&[0x02]);
        let message_result = message_mac.finalize().into_bytes();

        self.chain_key.copy_from_slice(&chain_result);
        self.index += 1;

        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&message_result);
        message_key
    }

    pub(crate) fn get_index(&self) -> u32 {
        self.index
    }

    pub(crate) fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[0..4].copy_from_slice(&self.index.to_be_bytes());
        bytes[4..36].copy_from_slice(&self.chain_key);

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8; 36]) -> Chain {
        let mut index_bytes = [0u8; 4];
        index_bytes.copy_from_slice(&bytes[..4]);
        let index = u32::from_be_bytes(index_bytes);

        let mut ck_bytes = [0u8; 32];
        ck_bytes.copy_from_slice(&bytes[4..]);

        Chain {
            index,
            chain_key: ck_bytes,
        }
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

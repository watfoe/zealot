use crate::ratchet::chain::Chain;
use crate::{X25519PublicKey, X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub(crate) struct RatchetState {
    pub(crate) dh_pair: X25519Secret,

    pub(crate) remote_dh_key_public: Option<X25519PublicKey>,

    pub(crate) root_key: Box<[u8; 32]>,
    pub(crate) sending_chain: Chain,
    pub(crate) receiving_chain: Chain,

    // Message counters
    pub(crate) previous_sending_chain_length: u32,
    pub(crate) sending_message_number: u32,
    pub(crate) receiving_message_number: u32,

    pub(crate) sending_header_key: Option<Box<[u8; 32]>>,
    pub(crate) receiving_header_key: Option<Box<[u8; 32]>>,
    pub(crate) next_sending_header_key: Box<[u8; 32]>,
    pub(crate) next_receiving_header_key: Option<Box<[u8; 32]>>,
}

impl Zeroize for RatchetState {
    fn zeroize(&mut self) {
        self.dh_pair.zeroize();

        self.root_key.zeroize();
        self.sending_chain.zeroize();
        self.receiving_chain.zeroize();

        self.sending_header_key.as_mut().map(|key| key.zeroize());
        self.receiving_header_key.as_mut().map(|key| key.zeroize());
        self.next_receiving_header_key
            .as_mut()
            .map(|key| key.zeroize());
    }
}

impl ZeroizeOnDrop for RatchetState {}

use crate::chain::Chain;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct RatchetState {
    pub(crate) dh_pair: StaticSecret,

    pub(crate) dh_remote_public: Option<PublicKey>,

    pub(crate) root_key: [u8; 32],
    pub(crate) sending_chain: Chain,
    pub(crate) receiving_chain: Chain,

    // Message counters
    pub(crate) previous_sending_chain_length: u32,
    pub(crate) sending_message_number: u32,
    pub(crate) receiving_message_number: u32,

    pub(crate) sending_header_key: Option<[u8; 32]>,
    pub(crate) receiving_header_key: Option<[u8; 32]>,
    pub(crate) next_sending_header_key: [u8; 32],
    pub(crate) next_receiving_header_key: Option<[u8; 32]>,
}

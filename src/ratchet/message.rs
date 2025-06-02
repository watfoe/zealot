use crate::{Error, X25519PublicKey};

/// Header for a ratchet message
#[derive(Clone, Debug)]
pub(super) struct MessageHeader {
    pub(super) public_key: X25519PublicKey,
    pub(super) previous_chain_length: u32,
    pub(super) message_number: u32,
}

impl MessageHeader {
    pub(super) fn to_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        bytes[0..32].copy_from_slice(self.public_key.as_bytes());
        bytes[32..36].copy_from_slice(&self.previous_chain_length.to_be_bytes());
        bytes[36..40].copy_from_slice(&self.message_number.to_be_bytes());

        bytes
    }
}

impl From<[u8; 40]> for MessageHeader {
    fn from(bytes: [u8; 40]) -> Self {
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&bytes[0..32]);

        let mut pn_bytes = [0u8; 4];
        pn_bytes.copy_from_slice(&bytes[32..36]);

        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&bytes[36..40]);

        let public_key = X25519PublicKey::from(dh_bytes);
        let previous_chain_length = u32::from_be_bytes(pn_bytes);
        let message_number = u32::from_be_bytes(n_bytes);

        Self {
            public_key,
            previous_chain_length,
            message_number,
        }
    }
}

/// An encrypted message in the Double Ratchet protocol.
///
/// Contains an encrypted header with metadata and the encrypted message payload.
#[derive(Clone)]
pub struct RatchetMessage {
    /// Encrypted header containing ratchet metadata.
    pub header: Vec<u8>,
    /// Encrypted message payload.
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// Serializes the message to bytes for transmission.
    ///
    /// Format: [header length (4 bytes)][header][ciphertext]
    pub fn to_bytes(self) -> Vec<u8> {
        // Format: [header length][header][ciphertext]
        let mut result = Vec::with_capacity(4 + self.header.len() + self.ciphertext.len());
        let len = self.header.len() as u32;
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.header);
        result.extend_from_slice(&self.ciphertext);

        result
    }

    /// Deserializes a message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::Protocol("Invalid message format".to_string()));
        }

        let header_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        if bytes.len() < 4 + header_len {
            return Err(Error::Protocol("Invalid message format".to_string()));
        }

        Ok(Self {
            header: bytes[4..4 + header_len].to_vec(),
            ciphertext: bytes[4 + header_len..].to_vec(),
        })
    }
}

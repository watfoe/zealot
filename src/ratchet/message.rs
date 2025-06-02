use crate::{Error, X25519PublicKey};

/// Header for a ratchet message
#[derive(Clone, Debug)]
pub struct MessageHeader {
    /// TODO: Add documentation here
    pub public_key: X25519PublicKey,
    /// TODO: Add documentation here
    pub previous_chain_length: u32,
    /// TODO: Add documentation here
    pub message_number: u32,
}

impl MessageHeader {
    /// TODO: Add documentation here
    pub fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.public_key.as_bytes());
        buffer.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        buffer.extend_from_slice(&self.message_number.to_be_bytes());
    }

    /// TODO: Add documentation here
    pub fn to_bytes(&self) -> [u8; 40] {
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

/// TODO: Add documentation here
#[derive(Clone)]
pub struct RatchetMessage {
    /// TODO: Add documentation here
    pub header: Vec<u8>,
    /// TODO: Add documentation here
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// TODO: Add documentation here
    pub fn to_bytes(self) -> Vec<u8> {
        // Format: [header length][header][ciphertext]
        let mut result = Vec::with_capacity(4 + self.header.len() + self.ciphertext.len());
        let len = self.header.len() as u32;
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.header);
        result.extend_from_slice(&self.ciphertext);

        result
    }

    /// TODO: Add documentation here
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

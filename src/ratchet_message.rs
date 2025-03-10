use x25519_dalek::PublicKey;

/// Header for a ratchet message
#[derive(Clone, Debug)]
pub struct MessageHeader {
    pub public_key: PublicKey,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

impl MessageHeader {
    pub fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.public_key.as_bytes());
        buffer.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        buffer.extend_from_slice(&self.message_number.to_be_bytes());
    }

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

        let public_key = PublicKey::from(dh_bytes);
        let previous_chain_length = u32::from_be_bytes(pn_bytes);
        let message_number = u32::from_be_bytes(n_bytes);

        Self {
            public_key,
            previous_chain_length,
            message_number,
        }
    }
}

#[derive(Clone)]
pub struct RatchetMessage {
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        // Format: [header][ciphertext]
        let mut result = Vec::with_capacity(self.header.len() + self.ciphertext.len());
        result.extend_from_slice(&self.header);
        result.extend_from_slice(&self.ciphertext);

        result
    }
}

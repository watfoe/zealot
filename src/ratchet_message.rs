use x25519_dalek::PublicKey;
use crate::Error;

/// Header for a ratchet message
#[derive(Clone, Copy)]
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

    pub fn serialize_to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 4 + 4);
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        bytes.extend_from_slice(&self.message_number.to_be_bytes());

        bytes
    }

    /// Deserialize a header from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 32 + 4 + 4 {
            return Err(Error::Protocol("Invalid header length".to_string()));
        }

        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&bytes[0..32]);

        let mut pn_bytes = [0u8; 4];
        pn_bytes.copy_from_slice(&bytes[32..36]);

        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&bytes[36..40]);

        let public_key = PublicKey::from(dh_bytes);
        let previous_chain_length = u32::from_be_bytes(pn_bytes);
        let message_number = u32::from_be_bytes(n_bytes);

        Ok(MessageHeader {
            public_key,
            previous_chain_length,
            message_number,
        })
    }
}

#[derive(Clone)]
pub struct RatchetMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    pub fn serialize(&self) -> Vec<u8> {
        // Format: [header_length(2 bytes)][header][ciphertext]
        let header_bytes = self.header.serialize_to_vec();
        let header_len = header_bytes.len() as u16;

        let mut result = Vec::with_capacity(2 + header_bytes.len() + self.ciphertext.len());
        result.extend_from_slice(&header_len.to_be_bytes());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&self.ciphertext);

        result
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::Protocol("Message too short".to_string()));
        }

        let mut header_len_bytes = [0u8; 2];
        header_len_bytes.copy_from_slice(&bytes[0..2]);
        let header_len = u16::from_be_bytes(header_len_bytes) as usize;

        if bytes.len() < 2 + header_len {
            return Err(Error::Protocol("Invalid message format".to_string()));
        }

        let header = MessageHeader::deserialize(&bytes[2..2+header_len])?;
        let ciphertext = bytes[2+header_len..].to_vec();

        Ok(RatchetMessage { header, ciphertext })
    }
}

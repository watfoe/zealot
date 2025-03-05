use crate::{DoubleRatchet, Error, RatchetMessage};

// Session management
pub struct Session {
    session_id: String,
    ratchet: DoubleRatchet,
    created_at: std::time::SystemTime,
    last_used_at: std::time::SystemTime,
    is_initiator: bool
}

impl Session {
    pub fn new(session_id: String, ratchet: DoubleRatchet, is_initiator: bool) -> Self {
        let now = std::time::SystemTime::now();
        Self {
            session_id,
            ratchet,
            created_at: now,
            last_used_at: now,
            is_initiator
        }
    }

    /// A session ID is the SHA256 of the concatenation of three SessionKeys,
    /// the account’s identity key, the ephemeral base key and the one-time key which
    /// is used to establish the session.
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Error> {
        self.last_used_at = std::time::SystemTime::now();
        let message = self.ratchet.encrypt(plaintext, associated_data)?;
        Ok(message.serialize())
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Error> {
        self.last_used_at = std::time::SystemTime::now();
        let message = RatchetMessage::deserialize(ciphertext)?;
        self.ratchet.decrypt(message, associated_data)
    }

    pub fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        todo!()
    }
}

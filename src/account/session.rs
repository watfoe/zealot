use crate::X25519PublicKey;
use crate::{DoubleRatchet, Error, RatchetMessage};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X3DH Key materials that were used to establish this outbound session by `Alice`.
///
/// Share this with the recipient `Bob` so that they can create an inbound session.
/// Once they have established a session. Mark this session as established with:
///
/// ```text
/// session.mark_as_established();
/// ```
///
/// This transforms the session into a more compact format for serialization. Subsequent messages
/// to `Bob` can also then omit this so as to be more compact.
#[derive(Clone, Copy)]
pub struct OutboundSessionX3DHKeys {
    /// ID of `Bob's` the signed pre-key used in X3DH key agreement.
    pub spk_id: u32,
    /// ID of `Bob's` one-time pre-key used in X3DH key agreement.
    pub otpk_id: Option<u32>,
    /// Ephemeral public key from X3DH key agreement.
    pub ephemeral_key_public: X25519PublicKey,
}

/// A secure messaging session between two parties.
///
/// Represents an established secure communication channel using the Signal Protocol.
/// Encapsulates a Double Ratchet instance along with metadata about the session.
///
/// Sessions are typically created after a successful X3DH key agreement and
/// are used to encrypt and decrypt messages between the two parties.
pub struct Session {
    /// A probabilistically globally unique identifier for this session.
    pub(crate) session_id: String,
    pub(crate) ratchet: DoubleRatchet,
    /// X3DH Key materials that were used to establish this outbound session by `Alice`.
    pub(crate) x3dh_keys: Option<OutboundSessionX3DHKeys>,
}

impl Session {
    /// Creates a new session with the given parameters.
    pub(crate) fn new(
        session_id: String,
        ratchet: DoubleRatchet,
        x3dh_keys: Option<OutboundSessionX3DHKeys>,
    ) -> Self {
        Self {
            session_id,
            ratchet,
            x3dh_keys,
        }
    }

    /// Encrypts a message using this session.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, Error> {
        self.ratchet.encrypt(plaintext)
    }

    /// Decrypts a message using this session.
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>, Error> {
        self.ratchet.decrypt(message)
    }

    /// Marks this session as established end-to-end.
    pub fn mark_as_established(&mut self) {
        self.x3dh_keys = None;
    }

    /// Returns a probabilistically globally unique identifier for this session.
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    /// Returns X3DH Key materials that were used to establish this outbound session by `Alice`.
    pub fn x3dh_keys(&self) -> Option<OutboundSessionX3DHKeys> {
        self.x3dh_keys
    }
}

impl Zeroize for Session {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.ratchet.zeroize();
        self.x3dh_keys = None;
    }
}

impl ZeroizeOnDrop for Session {}

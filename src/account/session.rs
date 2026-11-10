use crate::X25519PublicKey;
use crate::{DoubleRatchet, Error, RatchetMessage};
use ed25519_dalek::VerifyingKey;
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
/// to `Bob` can also then omit this.
#[derive(Clone, Copy)]
pub struct OutboundSessionX3DHKeys {
    /// ID of `Bob's` the signed pre-key used in X3DH key agreement.
    pub spk_id: u32,
    /// ID of `Bob's` one-time pre-key used in X3DH key agreement.
    pub otpk_id: Option<u32>,
    /// Ephemeral public key from X3DH key agreement.
    pub ephemeral_key_public: X25519PublicKey,
}

/// Represents an established secure communication channel using the Signal Protocol.
/// Encapsulates a Double Ratchet instance along with metadata about the session.
///
/// Sessions are typically created after a successful X3DH key agreement and
/// are used to encrypt and decrypt messages between the two parties.
pub struct Session {
    /// A probabilistically, globally unique identifier for this session.
    pub(crate) session_id: String,
    /// Peer's public IdentityKey used to establish this session
    pub(crate) peer_ik_public: X25519PublicKey,
    /// Peer's public Ed25519 identity key this session is bound to.
    pub(crate) peer_signing_key_public: VerifyingKey,
    pub(crate) ratchet: DoubleRatchet,
    /// X3DH Key materials that were used to establish this outbound session by `Alice`.
    pub(crate) x3dh_keys: Option<OutboundSessionX3DHKeys>,
}

impl Session {
    /// Creates a new session with the given parameters.
    pub(crate) fn new(
        session_id: String,
        peer_ik_public: X25519PublicKey,
        peer_signing_key_public: VerifyingKey,
        ratchet: DoubleRatchet,
        x3dh_keys: Option<OutboundSessionX3DHKeys>,
    ) -> Self {
        Self {
            session_id,
            peer_ik_public,
            peer_signing_key_public,
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

    /// Returns the identifier for this session.
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    /// Returns the peer's public X25519 identity key used to establish this
    /// session.
    ///
    /// This is only half of the peer's identity; see
    /// [`Self::peer_signing_key_public`].
    pub fn peer_ik_public(&self) -> X25519PublicKey {
        self.peer_ik_public
    }

    /// Returns the peer's public Ed25519 identity key this session is bound
    /// to.
    ///
    /// For an outbound session this is the key that signed the pre-key the
    /// session was built from, taken from the bundle as it was received. For
    /// an inbound session it is the key the initiator was said to hold. Either
    /// way the session only works if the peer bound the same keys, but that
    /// alone does not tell you the keys belong to the person you meant to
    /// reach: check this key and [`Self::peer_ik_public`] together against
    /// the identity you expect.
    pub fn peer_signing_key_public(&self) -> VerifyingKey {
        self.peer_signing_key_public
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

impl Drop for Session {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Session {}

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
    /// Unique identifier for this session.
    pub session_id: String,
    pub(crate) ratchet: DoubleRatchet,
    /// X3DH Key materials that were used to establish this outbound session by `Alice`.
    pub x3dh_keys: Option<OutboundSessionX3DHKeys>,
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
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RatchetMessage, Error> {
        self.ratchet.encrypt(plaintext, associated_data)
    }

    /// Decrypts a message using this session.
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.ratchet.decrypt(message, associated_data)
    }

    /// Marks this session as established end-to-end.
    pub fn mark_as_established(&mut self) {
        self.x3dh_keys = None;
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

#[cfg(test)]
mod tests {
    use crate::{
        DoubleRatchet, IdentityKey, OneTimePreKey, OutboundSessionX3DHKeys, Session, SignedPreKey,
        X3DH, X3DHPublicKeys,
    };

    #[test]
    fn test_session() {
        let alice_identity = IdentityKey::new().unwrap();
        let bob_identity = IdentityKey::new().unwrap();
        let bob_signed_pre_key = SignedPreKey::new(1).unwrap();
        let bob_one_time_pre_key = OneTimePreKey::new(1).unwrap();
        let bob_bundle = X3DHPublicKeys::new(
            bob_identity.dh_key_public(),
            bob_identity.signing_key_public(),
            bob_signed_pre_key.signature(&bob_identity),
            (bob_signed_pre_key.id(), bob_signed_pre_key.public_key()),
            Some((bob_one_time_pre_key.id(), bob_one_time_pre_key.public_key())),
        );

        // Alice performs X3DH with Bob's bundle
        let x3dh = X3DH::new(b"Protocol");
        let x3dh_result = x3dh
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        let x3dh_ephemeral_public = x3dh_result.public_key();
        // Alice initializes her Double Ratchet
        let alice_ratchet = DoubleRatchet::initialize_for_alice(
            x3dh_result.shared_secret(),
            &bob_bundle.spk_public().1,
        );

        // Create a session ID for Alice
        let alice_session_id = "alice-to-bob".to_string();
        let mut alice_session = Session::new(
            alice_session_id,
            alice_ratchet,
            Some(OutboundSessionX3DHKeys {
                spk_id: 1,
                ephemeral_key_public: x3dh_ephemeral_public,
                otpk_id: Some(1),
            }),
        );

        // Bob processes Alice's initiation
        let bob_shared_secret = x3dh
            .initiate_for_bob(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.dh_key_public(),
                &x3dh_ephemeral_public,
            )
            .unwrap();

        // Bob initializes his Double Ratchet
        let bob_ratchet =
            DoubleRatchet::initialize_for_bob(bob_shared_secret, bob_signed_pre_key.key_pair());

        // Create a session ID for Bob
        let bob_session_id = "bob-to-alice".to_string();
        let mut bob_session = Session::new(bob_session_id, bob_ratchet, None);

        // Alice encrypts a message for Bob
        let message = "Hello Bob, this is a secure message!";
        let associated_data = b"session-1";
        let erm = alice_session
            .encrypt(message.as_bytes(), associated_data)
            .unwrap();

        // Bob decrypts Alice's message
        let decrypted = bob_session.decrypt(&erm, associated_data).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), message);

        // Bob responds to Alice
        let response = "Hello Alice, I received your message!";
        let erm = bob_session
            .encrypt(response.as_bytes(), associated_data)
            .unwrap();

        // Alice decrypts Bob's response
        let decrypted_response = alice_session.decrypt(&erm, associated_data).unwrap();
        assert_eq!(String::from_utf8(decrypted_response).unwrap(), response);
    }
}

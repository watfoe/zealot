use crate::X25519PublicKey;
use crate::{DoubleRatchet, Error, RatchetMessage};
use std::time::SystemTime;

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
    /// When this session was created.
    pub created_at: SystemTime,
    /// When this session was last used for encryption or decryption.
    pub last_used_at: SystemTime,
    /// ID of the signed pre-key used in X3DH key agreement.
    pub x3dh_spk_id: Option<u32>,
    /// ID of the one-time pre-key used in X3DH key agreement.
    pub x3dh_otpk_id: Option<u32>,
    /// Ephemeral public key from X3DH key agreement.
    pub x3dh_ephemeral_key_public: Option<X25519PublicKey>,
}

impl Session {
    /// Creates a new session with the given parameters.
    pub(crate) fn new(
        session_id: String,
        ratchet: DoubleRatchet,
        x3dh_spk_id: Option<u32>,
        x3dh_otpk_id: Option<u32>,
        x3dh_ephemeral_key_public: Option<X25519PublicKey>,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            session_id,
            ratchet,
            created_at: now,
            last_used_at: now,
            x3dh_spk_id,
            x3dh_otpk_id,
            x3dh_ephemeral_key_public,
        }
    }

    /// Encrypts a message using this session.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RatchetMessage, Error> {
        self.last_used_at = SystemTime::now();
        self.ratchet.encrypt(plaintext, associated_data)
    }

    /// Decrypts a message using this session.
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.last_used_at = SystemTime::now();
        self.ratchet.decrypt(message, associated_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        DoubleRatchet, IdentityKey, OneTimePreKey, Session, SignedPreKey, X3DH, X3DHPublicKeys,
    };

    // Helper function to set up a test session pair
    fn create_session_pair() -> (Session, Session) {
        // Set up identities and pre-keys
        let alice_identity = IdentityKey::new().unwrap();
        let bob_identity = IdentityKey::new().unwrap();
        let bob_signed_pre_key = SignedPreKey::new(1).unwrap();
        let bob_one_time_pre_key = OneTimePreKey::new(1).unwrap();

        // Create Bob's pre-key bundle
        let bob_bundle = X3DHPublicKeys::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Alice performs X3DH with Bob's bundle
        let x3dh = X3DH::new(b"Test-Session-Protocol");
        let alice_x3dh_result = x3dh
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();
        let alice_ephemeral_public = alice_x3dh_result.public_key();

        let alice_x3dh_pub_key = alice_x3dh_result.public_key();

        // Alice initializes her Double Ratchet
        let alice_ratchet = DoubleRatchet::initialize_for_alice(
            alice_x3dh_result.shared_secret(),
            &bob_bundle.spk_public().1,
        );

        // Create a session ID for Alice
        let alice_session_id = format!("alice-to-bob-{}", rand::random::<u32>());
        let alice_session = Session::new(
            alice_session_id,
            alice_ratchet,
            None,
            None,
            Some(alice_x3dh_pub_key),
        );

        // Bob processes Alice's initiation
        let bob_shared_secret = x3dh
            .initiate_for_bob(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.dh_key_public(),
                &alice_ephemeral_public,
            )
            .unwrap();

        // Bob initializes his Double Ratchet
        let bob_ratchet =
            DoubleRatchet::initialize_for_bob(bob_shared_secret, bob_signed_pre_key.key_pair());

        // Create a session ID for Bob
        let bob_session_id = format!("bob-to-alice-{}", rand::random::<u32>());
        let bob_session = Session::new(bob_session_id, bob_ratchet, None, None, None);

        (alice_session, bob_session)
    }

    #[test]
    fn test_session_basic_communication() {
        let (mut alice_session, mut bob_session) = create_session_pair();

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

    #[test]
    fn test_session_multiple_messages() {
        let (mut alice_session, mut bob_session) = create_session_pair();
        let associated_data = b"session-multiple";

        // Exchange multiple messages
        for i in 1..10 {
            // Alice to Bob
            let message = format!("Message {} from Alice", i);
            let erm = alice_session
                .encrypt(message.as_bytes(), associated_data)
                .unwrap();
            let decrypted = bob_session.decrypt(&erm, associated_data).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), message);

            // Bob to Alice
            let response = format!("Response {} from Bob", i);
            let erm = bob_session
                .encrypt(response.as_bytes(), associated_data)
                .unwrap();
            let decrypted_response = alice_session.decrypt(&erm, associated_data).unwrap();
            assert_eq!(String::from_utf8(decrypted_response).unwrap(), response);
        }
    }

    #[test]
    fn test_session_different_associated_data() {
        let (mut alice_session, mut bob_session) = create_session_pair();

        // Alice encrypts a message with specific associated data
        let message = "Secret message with special AD";
        let associated_data_1 = b"special-context-1";
        let erm = alice_session
            .encrypt(message.as_bytes(), associated_data_1)
            .unwrap();

        // Bob tries to decrypt with wrong associated data
        let associated_data_2 = b"different-context";
        let result = bob_session.decrypt(&erm, associated_data_2);
        assert!(result.is_err(), "Decryption with wrong AD should fail");

        // Bob decrypts with correct associated data
        let decrypted = bob_session.decrypt(&erm, associated_data_1).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), message);
    }

    #[test]
    fn test_session_id_uniqueness() {
        // Create multiple session pairs and verify IDs are unique
        let mut session_ids = Vec::new();

        for _ in 0..10 {
            let (alice_session, bob_session) = create_session_pair();
            session_ids.push(alice_session.session_id);
            session_ids.push(bob_session.session_id);
        }

        // Verify all IDs are unique
        let mut unique_ids = session_ids.clone();
        unique_ids.sort();
        unique_ids.dedup();

        assert_eq!(
            unique_ids.len(),
            session_ids.len(),
            "Session IDs should be unique"
        );
    }
}

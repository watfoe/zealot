use crate::{DoubleRatchet, Error, RatchetMessage};

// Session management
pub struct Session {
    session_id: String,
    ratchet: DoubleRatchet,
    created_at: std::time::SystemTime,
    last_used_at: std::time::SystemTime,
    is_initiator: bool,
}

impl Session {
    pub fn new(session_id: String, ratchet: DoubleRatchet, is_initiator: bool) -> Self {
        let now = std::time::SystemTime::now();
        Self {
            session_id,
            ratchet,
            created_at: now,
            last_used_at: now,
            is_initiator,
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
        Ok(message.to_bytes())
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Error> {
        self.last_used_at = std::time::SystemTime::now();
        let message = RatchetMessage::from_bytes(ciphertext)?;
        self.ratchet.decrypt(message, associated_data)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{DoubleRatchet, IdentityKey, OneTimePreKey, PreKeyBundle, Session, SignedPreKey, X3DH};

    // Helper function to set up a test session pair
    fn create_session_pair() -> (Session, Session) {
        // Set up identities and pre-keys
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);

        // Create Bob's pre-key bundle
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Alice performs X3DH with Bob's bundle
        let x3dh = X3DH::new(b"Test-Session-Protocol");
        let alice_x3dh_result = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();
        let alice_ephemeral_public = alice_x3dh_result.get_public_key();

        // Alice initializes her Double Ratchet
        let alice_ratchet = DoubleRatchet::initialize_as_first_sender(
            &alice_x3dh_result.get_shared_secret(),
            &bob_bundle.get_signed_pre_key_public(),
        );

        // Create a session ID for Alice
        let alice_session_id = format!("alice-to-bob-{}", rand::random::<u32>());
        let alice_session = Session::new(alice_session_id, alice_ratchet, true);

        // Bob processes Alice's initiation
        let bob_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_ephemeral_public,
            )
            .unwrap();

        // Bob initializes his Double Ratchet
        let bob_ratchet = DoubleRatchet::initialize_as_first_receiver(
            &bob_shared_secret,
            bob_signed_pre_key.get_key_pair(),
        );

        // Create a session ID for Bob
        let bob_session_id = format!("bob-to-alice-{}", rand::random::<u32>());
        let bob_session = Session::new(bob_session_id, bob_ratchet, false);

        (alice_session, bob_session)
    }

    #[test]
    fn test_session_basic_communication() {
        let (mut alice_session, mut bob_session) = create_session_pair();

        // Alice encrypts a message for Bob
        let message = "Hello Bob, this is a secure message!";
        let associated_data = b"session-1";
        let encrypted = alice_session.encrypt(message.as_bytes(), associated_data).unwrap();

        // Bob decrypts Alice's message
        let decrypted = bob_session.decrypt(&encrypted, associated_data).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), message);

        // Bob responds to Alice
        let response = "Hello Alice, I received your message!";
        let encrypted_response = bob_session.encrypt(response.as_bytes(), associated_data).unwrap();

        // Alice decrypts Bob's response
        let decrypted_response = alice_session.decrypt(&encrypted_response, associated_data).unwrap();
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
            let encrypted = alice_session.encrypt(message.as_bytes(), associated_data).unwrap();
            let decrypted = bob_session.decrypt(&encrypted, associated_data).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), message);

            // Bob to Alice
            let response = format!("Response {} from Bob", i);
            let encrypted_response = bob_session.encrypt(response.as_bytes(), associated_data).unwrap();
            let decrypted_response = alice_session.decrypt(&encrypted_response, associated_data).unwrap();
            assert_eq!(String::from_utf8(decrypted_response).unwrap(), response);
        }
    }

    #[test]
    fn test_session_different_associated_data() {
        let (mut alice_session, mut bob_session) = create_session_pair();

        // Alice encrypts a message with specific associated data
        let message = "Secret message with special AD";
        let associated_data_1 = b"special-context-1";
        let encrypted = alice_session.encrypt(message.as_bytes(), associated_data_1).unwrap();

        // Bob tries to decrypt with wrong associated data
        let associated_data_2 = b"different-context";
        let result = bob_session.decrypt(&encrypted, associated_data_2);
        assert!(result.is_err(), "Decryption with wrong AD should fail");

        // Bob decrypts with correct associated data
        let decrypted = bob_session.decrypt(&encrypted, associated_data_1).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), message);
    }

    #[test]
    fn test_session_id_uniqueness() {
        // Create multiple session pairs and verify IDs are unique
        let mut session_ids = Vec::new();

        for _ in 0..10 {
            let (alice_session, bob_session) = create_session_pair();
            session_ids.push(alice_session.session_id());
            session_ids.push(bob_session.session_id());
        }

        // Verify all IDs are unique
        let mut unique_ids = session_ids.clone();
        unique_ids.sort();
        unique_ids.dedup();

        assert_eq!(unique_ids.len(), session_ids.len(), "Session IDs should be unique");
    }
}

use crate::config::AccountConfig;
use crate::one_time_pre_key::OneTimePreKeyStore;
use crate::{
    DoubleRatchet, Error, IdentityKey, PreKeyBundle, Session, SignedPreKey, X3DH, X25519PublicKey,
};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// An `Account` represents a user in the Signal Protocol ecosystem, managing
/// identity keys, pre-keys, and established sessions. It provides methods for
/// creating and managing secure communication sessions with other users.
pub struct Account {
    pub(crate) ik: IdentityKey,
    pub(crate) spk: SignedPreKey,
    pub(crate) spk_last_rotation: std::time::SystemTime,
    pub(crate) otpk_store: OneTimePreKeyStore,
    pub(crate) sessions: HashMap<String, Session>, // session_id -> Session
    pub(crate) config: AccountConfig,
}

impl Account {
    /// Creates a new account with the given configuration.
    ///
    /// If no configuration is provided, default values are used.
    pub fn new(config: Option<AccountConfig>) -> Self {
        let config = config.unwrap_or_default();

        let ik = IdentityKey::new();
        let spk = SignedPreKey::new(1);
        let now = std::time::SystemTime::now();

        let mut otpk_store = OneTimePreKeyStore::new(config.max_one_time_pre_keys);
        otpk_store.generate_keys(config.max_one_time_pre_keys);

        Self {
            ik,
            spk,
            spk_last_rotation: now,
            otpk_store,
            sessions: HashMap::new(),
            config,
        }
    }

    /// Returns the pre-key bundle and one-time pre-keys for this account.
    pub fn prekey_bundle(&mut self) -> (PreKeyBundle, HashMap<u32, X25519PublicKey>) {
        self.maybe_rotate_spk();
        self.maybe_replenish_otpk_store();

        let otpks = self.otpk_store.get_public_keys();

        (PreKeyBundle::new(&self.ik, &self.spk, None), otpks)
    }

    /// Returns the configuration for this account.
    pub fn config(&self) -> AccountConfig {
        self.config.clone()
    }

    /// Initiates a new session with another user (Bob).
    ///
    /// This implements the initiator's (Alice's) side of the X3DH protocol,
    /// using the pre-key bundle retrieved from the other user (Bob).
    pub fn create_outbound_session(
        &mut self,
        their_bundle: &PreKeyBundle,
    ) -> Result<String, Error> {
        let x3dh = X3DH::new(&self.config.protocol_info);
        let x3dh_result = x3dh.initiate(&self.ik, their_bundle)?;

        let session_id = self.derive_session_id(
            &their_bundle.public_identity_key(),
            &x3dh_result.public_key(),
        );

        let ratchet = DoubleRatchet::initialize_for_alice(
            x3dh_result.shared_secret(),
            &their_bundle.public_signed_pre_key(),
        );

        let session = Session::new(session_id.clone(), ratchet, true);

        self.sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// Processes an incoming session initiation from another user (Alice).
    ///
    /// This implements the responder's (Bob's) side of the X3DH protocol,
    /// using the identity key, ephemeral key, and pre-key IDs from the
    /// initiator (Alice).
    pub fn create_inbound_session(
        &mut self,
        their_ik: &X25519PublicKey,
        their_ephemeral_key: &X25519PublicKey,
        spk_id: u32,
        one_time_pre_key_id: Option<u32>,
    ) -> Result<String, Error> {
        if self.spk.id() != spk_id {
            return Err(Error::PreKey("Invalid signed pre-key ID".to_string()));
        }

        let one_time_pre_key = if let Some(id) = one_time_pre_key_id {
            // Remove the one-time pre-key from the store once used
            Some(
                self.otpk_store
                    .take(id)
                    .ok_or_else(|| Error::PreKey("One-time pre-key not found".to_string()))?,
            )
        } else {
            None
        };

        // Process X3DH
        let x3dh = X3DH::new(&self.config.protocol_info);
        let shared_secret = x3dh.process_initiation(
            &self.ik,
            &self.spk,
            one_time_pre_key,
            their_ik,
            their_ephemeral_key,
        )?;

        // Initialize Double Ratchet
        let ratchet = DoubleRatchet::initialize_for_bob(shared_secret, self.spk.key_pair());

        // Create a unique session ID
        let session_id = self.derive_session_id(their_ik, their_ephemeral_key);

        // Create and store the session
        let session = Session::new(session_id.clone(), ratchet, false);

        self.sessions.insert(session_id.clone(), session);

        // Check if we need more one-time pre-keys
        self.maybe_replenish_otpk_store();

        Ok(session_id)
    }

    /// Returns a reference to a session by its ID.
    pub fn session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    /// Returns a mutable reference to a session by its ID.
    pub fn session_mut(&mut self, session_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    // Periodically rotate the signed pre-key
    fn maybe_rotate_spk(&mut self) {
        let now = std::time::SystemTime::now();
        if now
            .duration_since(self.spk_last_rotation)
            .unwrap_or_default()
            >= self.config.signed_pre_key_rotation_interval
        {
            let new_id = self.spk.id() + 1;
            self.spk = SignedPreKey::new(new_id);
            self.spk_last_rotation = now;
        }
    }

    // Ensure we have enough one-time pre-keys
    fn maybe_replenish_otpk_store(&mut self) {
        if self.otpk_store.count() < self.config.min_one_time_pre_keys {
            self.otpk_store.replenish();
        }
    }

    /// Derive a unique session ID from identities
    ///
    /// A session ID is the SHA256 of the concatenation of three SessionKeys,
    /// the account’s identity key, the ephemeral base key and the one-time key which
    /// is used to establish the session.
    fn derive_session_id(
        &self,
        their_identity: &X25519PublicKey,
        ephemeral_key: &X25519PublicKey,
    ) -> String {
        let mut hasher = Sha256::new();

        // Include both identities and the ephemeral key
        hasher.update(self.ik.public_dh_key().as_bytes());
        hasher.update(their_identity.as_bytes());
        hasher.update(ephemeral_key.as_bytes());

        // Add randomness to prevent session ID collisions
        let mut random = [0u8; 16];
        rand::rng().fill_bytes(&mut random);
        hasher.update(random);
        let bytes = hasher.finalize();
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::account::Account;
    use crate::config::AccountConfig;
    use std::time::Duration;

    #[test]
    fn test_account_creation() {
        // Create with default config
        let account = Account::new(None);
        let config = account.config();

        // Verify default config values
        assert_eq!(config.max_skipped_messages, 100);
        assert!(config.min_one_time_pre_keys > 0);

        // Create with custom config
        let custom_config = AccountConfig {
            max_skipped_messages: 50,
            signed_pre_key_rotation_interval: Duration::from_secs(24 * 60 * 60), // 1 day
            min_one_time_pre_keys: 10,
            max_one_time_pre_keys: 50,
            protocol_info: b"Custom-Protocol".to_vec(),
        };

        let account = Account::new(Some(custom_config.clone()));
        let loaded_config = account.config();

        assert_eq!(
            loaded_config.max_skipped_messages,
            custom_config.max_skipped_messages
        );
        assert_eq!(
            loaded_config.min_one_time_pre_keys,
            custom_config.min_one_time_pre_keys
        );
    }

    #[test]
    fn test_account_key_bundle_generation() {
        let mut account = Account::new(None);

        // Get key bundle and verify it contains the expected components
        let (bundle, one_time_keys) = account.prekey_bundle();

        // Verify bundle properties
        assert!(
            bundle.verify().is_ok(),
            "Key bundle should have valid signature"
        );

        // Verify one-time keys
        assert!(
            !one_time_keys.is_empty(),
            "Should have generated one-time pre keys"
        );
    }

    #[test]
    fn test_account_session_management() {
        // Create two accounts
        let mut alice_account = Account::new(None);
        let mut bob_account = Account::new(None);

        // Get Bob's key bundle
        let (bob_bundle, _) = bob_account.prekey_bundle();

        // Alice initiates a session with Bob
        let alice_session_id = alice_account.create_outbound_session(&bob_bundle).unwrap();

        // Verify session was created and stored
        assert!(alice_account.session(&alice_session_id).is_some());

        // Send a message from Alice to Bob
        let alice_session = alice_account.session_mut(&alice_session_id).unwrap();
        let message = "Hello Bob!";
        let encrypted = alice_session.encrypt(message.as_bytes(), b"AD").unwrap();
    }

    #[test]
    fn test_key_rotation() {
        let config = AccountConfig {
            signed_pre_key_rotation_interval: Duration::from_millis(1),
            ..AccountConfig::default()
        };

        let mut account = Account::new(Some(config));

        let (initial_bundle, _) = account.prekey_bundle();
        let initial_spk_id = initial_bundle.signed_pre_key_id();

        std::thread::sleep(Duration::from_millis(10));

        let (new_bundle, _) = account.prekey_bundle();
        let new_spk_id = new_bundle.signed_pre_key_id();

        assert_ne!(
            initial_spk_id, new_spk_id,
            "Signed pre-key should have been rotated"
        );
    }
}

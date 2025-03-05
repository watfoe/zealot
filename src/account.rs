use std::collections::HashMap;
use base64::Engine;
use rand::{RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;
use crate::{DoubleRatchet, Error, IdentityKey, PreKeyBundle, Session, SignedPreKey, X3DH};
use crate::one_time_pre_key::OneTimePreKeyStore;

pub struct Account {
    ik: IdentityKey,

    spk: SignedPreKey,
    spk_last_rotation: std::time::SystemTime,
    otpk_store: OneTimePreKeyStore,

    sessions: HashMap<String, Session>, // session_id -> Session

    spk_rotation_interval: std::time::Duration,
    min_otpk_keys: usize,
}

impl Account {
    pub fn new() -> Self {
        let ik = IdentityKey::new();
        let spk = SignedPreKey::new(1);
        let now = std::time::SystemTime::now();

        let mut otpk_store = OneTimePreKeyStore::new(100);
        otpk_store.generate_keys(20); // Generate initial batch

        Self {
            ik,
            spk,
            spk_last_rotation: now,
            otpk_store,
            sessions: HashMap::new(),
            spk_rotation_interval: std::time::Duration::from_secs(7 * 24 * 60 * 60), // 1 week
            min_otpk_keys: 20,
        }
    }

    // Get the pre-key bundle for sharing with others
    pub fn get_key_bundle(&mut self) -> (PreKeyBundle, HashMap<u32, PublicKey>) {
        self.maybe_rotate_spk();
        self.maybe_replenish_otpk_store();

        let otpks = self.otpk_store.get_public_keys();

        (PreKeyBundle::new(&self.ik, &self.spk, None), otpks)
    }

    pub fn initiate_session(&mut self, their_bundle: &PreKeyBundle) -> Result<String, Error> {
        let x3dh = X3DH::new(b"Application-Specific-Info");
        let x3dh_result = x3dh.initiate(&self.ik, their_bundle)?;

        let session_id = self.derive_session_id(
            &their_bundle.get_identity_key_public(),
            &x3dh_result.get_public_key()
        );

        let ratchet = DoubleRatchet::initialize_as_first_sender(
            &x3dh_result.get_shared_secret(),
            &their_bundle.get_signed_pre_key_public()
        );

        let session = Session::new(
            session_id.clone(),
            ratchet,
            true
        );

        self.sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    // Process an incoming session initiation
    pub fn process_session_initiation(
        &mut self,
        their_ik: &PublicKey,
        their_ephemeral_key: &PublicKey,
        spk_id: u32,
        one_time_pre_key_id: Option<u32>
    ) -> Result<String, Error> {
        // Verify we have the required keys
        if self.spk.get_id() != spk_id {
            return Err(Error::PreKey("Invalid signed pre-key ID".to_string()));
        }

        let one_time_pre_key = if let Some(id) = one_time_pre_key_id {
            // Remove the one-time pre-key from the store once used
            Some(self.otpk_store.take(id).ok_or_else(||
                Error::PreKey("One-time pre-key not found".to_string())
            )?)
        } else {
            None
        };

        // Process X3DH
        let x3dh = X3DH::new(b"Application-Specific-Info");
        let shared_secret = x3dh.process_initiation(
            &self.ik,
            &self.spk,
            one_time_pre_key,
            their_ik,
            their_ephemeral_key
        )?;

        // Create a unique session ID
        let session_id = self.derive_session_id(
            their_ik,
            their_ephemeral_key
        );

        // Initialize Double Ratchet
        let ratchet = DoubleRatchet::initialize_as_first_receiver(
            &shared_secret,
            self.spk.get_key_pair()
        );

        // Create and store the session
        let session = Session::new(
            session_id.clone(),
            ratchet,
            false
        );

        self.sessions.insert(session_id.clone(), session);

        // Check if we need more one-time pre-keys
        self.maybe_replenish_otpk_store();

        Ok(session_id)
    }

    // Get an existing session by ID
    pub fn get_session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    // Get a mutable reference to an existing session
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    // Periodically rotate the signed pre-key
    fn maybe_rotate_spk(&mut self) {
        let now = std::time::SystemTime::now();
        if now.duration_since(self.spk_last_rotation)
            .unwrap_or_default() >= self.spk_rotation_interval {

            let new_id = self.spk.get_id() + 1;
            self.spk = SignedPreKey::new(new_id);
            self.spk_last_rotation = now;
        }
    }

    // Ensure we have enough one-time pre-keys
    fn maybe_replenish_otpk_store(&mut self) {
        if self.otpk_store.count() < self.min_otpk_keys {
            self.otpk_store.replenish();
        }
    }

    // Derive a unique session ID from identities
    fn derive_session_id(&self, their_identity: &PublicKey, ephemeral_key: &PublicKey) -> String {
        let mut hasher = Sha256::new();

        // Include both identities and the ephemeral key
        hasher.update(self.ik.get_public_dh_key().as_bytes());
        hasher.update(their_identity.as_bytes());
        hasher.update(ephemeral_key.as_bytes());

        // Add randomness to prevent session ID collisions
        let mut random = [0u8; 16];
        rand::rng().fill_bytes(&mut random);
        hasher.update(&random);
        let bytes = hasher.finalize();
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(&bytes)
    }

    // Serialization/deserialization methods for persistence
    // ...
}

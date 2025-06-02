mod config;
pub use config::*;
mod session;
pub use session::*;

use crate::X25519PublicKey;
use crate::{
    DoubleRatchet, Error, IdentityKey, SignedPreKey, SignedPreKeyStore, X3DH, generate_random_seed,
};
use crate::{OneTimePreKeyStore, X3DHPublicKeys};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::SystemTime;
use zeroize::Zeroize;

/// TODO: Add documentation here
pub struct AccountPreKeyBundle {
    /// TODO: Add documentation here
    pub ik_public: X25519PublicKey,
    /// TODO: Add documentation here
    pub signing_key_public: VerifyingKey,
    /// TODO: Add documentation here
    pub spk_public: (u32, X25519PublicKey),
    /// TODO: Add documentation here
    pub signature: Signature,
    /// TODO: Add documentation here
    pub otpks_public: HashMap<u32, X25519PublicKey>,
}

// TODO: Design for concurrency
// --- sessions: Arc<DashMap<String, Mutex<Session>>
// --- spk_store: Arc<RwLock<SignedPreKeyStore>
// --- spk_store: Arc<RwLock<SignedPreKeyStore>

/// An `Account` represents a user in the Signal Protocol ecosystem, managing
/// identity keys, pre-keys, and established sessions. It provides methods for
/// creating and managing secure communication sessions with other users.
pub struct Account {
    pub(crate) ik: IdentityKey,
    pub(crate) spk_last_rotation: SystemTime,
    pub(crate) sessions: HashMap<String, Session>, // session_id -> Session
    pub(crate) spk_store: SignedPreKeyStore,
    pub(crate) otpk_store: OneTimePreKeyStore,
    pub(crate) config: AccountConfig,
}

impl Account {
    /// Creates a new account with the given configuration.
    ///
    /// If no configuration is provided, default values are used.
    pub fn new(config: Option<AccountConfig>) -> Result<Self, Error> {
        let config = config.unwrap_or_default();

        let ik = IdentityKey::new()?;
        let now = SystemTime::now();

        let spk_store = SignedPreKeyStore::new(config.max_spks)?;

        let mut otpk_store = OneTimePreKeyStore::new(config.max_otpks);
        otpk_store.generate_keys(config.max_otpks)?;

        Ok(Self {
            ik,
            spk_store,
            spk_last_rotation: now,
            otpk_store,
            sessions: HashMap::new(),
            config,
        })
    }

    /// Returns the pre-key bundle and one-time pre-keys for this account.
    pub fn prekey_bundle(&self) -> AccountPreKeyBundle {
        AccountPreKeyBundle {
            ik_public: self.ik.dh_key_public(),
            signing_key_public: self.ik.signing_key_public(),
            spk_public: (self.spk().id(), self.spk().public_key()),
            signature: self.spk().signature(&self.ik),
            otpks_public: self.otpk_store.public_keys(),
        }
    }

    /// Returns the current signed-pre-key.
    pub fn spk(&self) -> &SignedPreKey {
        self.spk_store.get_current()
    }

    /// Returns the identity-key.
    pub fn ik(&self) -> &IdentityKey {
        &self.ik
    }

    /// Returns the configuration for this account.
    pub fn config(&self) -> &AccountConfig {
        &self.config
    }

    /// Initiates a new session with another user (Bob).
    ///
    /// This implements the initiator's (Alice's) side of the X3DH protocol,
    /// using the pre-key bundle retrieved from the other user (Bob).
    pub fn create_outbound_session(
        &mut self,
        bob_prekey_bundle: &X3DHPublicKeys,
    ) -> Result<String, Error> {
        let x3dh_result = X3DH::new(&self.config.protocol_info)
            .initiate_for_alice(&self.ik, bob_prekey_bundle)?;

        let session_id =
            self.derive_session_id(&bob_prekey_bundle.ik_public(), &x3dh_result.public_key())?;

        let x3dh_pub_key = x3dh_result.public_key();
        let ratchet = DoubleRatchet::initialize_for_alice(
            x3dh_result.shared_secret(),
            &bob_prekey_bundle.spk_public().1,
        );

        let session = Session::new(
            session_id.clone(),
            ratchet,
            Some(bob_prekey_bundle.spk_public().0),
            bob_prekey_bundle.otpk_public().map(|(id, _)| id),
            Some(x3dh_pub_key),
        );

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
        alice_ik_public: &X25519PublicKey,
        alice_ephemeral_key_public: &X25519PublicKey,
        spk_id: u32,
        otpk_id: Option<u32>,
    ) -> Result<String, Error> {
        let spk = if let Some(spk) = self.spk_store.get(spk_id) {
            spk
        } else {
            return Err(Error::PreKey("Invalid signed pre-key ID".to_string()));
        };

        let otpk = if let Some(id) = otpk_id {
            Some(
                self.otpk_store
                    .take(id)
                    .ok_or_else(|| Error::PreKey("One-time pre-key not found".to_string()))?,
            )
        } else {
            None
        };

        let shared_secret = X3DH::new(&self.config.protocol_info).initiate_for_bob(
            &self.ik,
            spk,
            otpk,
            alice_ik_public,
            alice_ephemeral_key_public,
        )?;

        let ratchet = DoubleRatchet::initialize_for_bob(shared_secret, self.spk().key_pair());
        let session_id = self.derive_session_id(alice_ik_public, alice_ephemeral_key_public)?;
        let session = Session::new(session_id.clone(), ratchet, None, None, None);

        self.sessions.insert(session_id.clone(), session);

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

    /// Periodically rotate the signed pre-key
    pub fn rotate_spk(&mut self) -> Result<Option<(u32, X25519PublicKey, Signature)>, Error> {
        let now = SystemTime::now();
        if now
            .duration_since(self.spk_last_rotation)
            .unwrap_or_default()
            >= self.config.spk_rotation_interval
        {
            let (id, spk) = self.spk_store.renew_key()?;
            self.spk_last_rotation = now;

            Ok(Some((id, spk.public_key(), spk.signature(&self.ik))))
        } else {
            Ok(None)
        }
    }

    /// Replenish one-time pre-keys
    pub fn replenish_otpks(&mut self) -> Result<HashMap<u32, X25519PublicKey>, Error> {
        self.otpk_store.replenish()
    }

    /// Derive a unique session ID from identities
    ///
    /// A session ID is the SHA256 of the concatenation of three SessionKeys,
    /// the account’s identity key, the ephemeral base key and the one-time key which
    /// is used to establish the session.
    fn derive_session_id(
        &self,
        their_dh_public: &X25519PublicKey,
        ephemeral_key_public: &X25519PublicKey,
    ) -> Result<String, Error> {
        let mut hasher = Sha256::new();

        // Include both identities and the ephemeral key
        hasher.update(self.ik.dh_key_public().as_bytes());
        hasher.update(their_dh_public.as_bytes());
        hasher.update(ephemeral_key_public.as_bytes());

        // Add randomness to prevent session ID collisions
        let mut random = generate_random_seed()?;
        hasher.update(random.as_slice());
        random.zeroize();

        let bytes = hasher.finalize();
        let engine = base64::engine::general_purpose::STANDARD;

        Ok(engine.encode(bytes))
    }
}

impl From<&AccountPreKeyBundle> for X3DHPublicKeys {
    fn from(value: &AccountPreKeyBundle) -> Self {
        Self {
            ik_public: value.ik_public,
            signing_key_public: value.signing_key_public,
            spk_public: (value.spk_public.0, value.spk_public.1),
            signature: value.signature,
            otpk_public: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::AccountConfig;
    use crate::{Account, X3DHPublicKeys};
    use std::time::Duration;

    #[test]
    fn test_account_key_bundle_generation() {
        let account = Account::new(None).unwrap();

        let account_bundle = account.prekey_bundle();
        let prekey_bundle = X3DHPublicKeys::from(&account_bundle);

        assert!(
            prekey_bundle.verify().is_ok(),
            "Key bundle should have valid signature"
        );

        assert!(
            !account_bundle.otpks_public.is_empty(),
            "Should have generated one-time pre keys"
        );
    }

    #[test]
    fn test_key_rotation() {
        let config = AccountConfig {
            spk_rotation_interval: Duration::from_millis(1),
            ..AccountConfig::default()
        };

        let mut account = Account::new(Some(config)).unwrap();

        let initial_bundle = account.prekey_bundle();
        let initial_spk_id = initial_bundle.spk_public.0;

        std::thread::sleep(Duration::from_millis(10));

        let (new_spk_id, _, _) = account.rotate_spk().unwrap().unwrap();

        assert_ne!(
            initial_spk_id, new_spk_id,
            "Signed pre-key should have been rotated"
        );
    }
}

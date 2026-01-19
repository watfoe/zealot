mod config;
pub use config::*;
mod session;
pub use session::*;

use crate::X25519PublicKey;
use crate::{DoubleRatchet, Error, IdentityKey, SignedPreKey, SignedPreKeyStore, X3DH};
use crate::{OneTimePreKeyStore, X3DHPublicKeys};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::SystemTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A bundle containing all public keys for an account.
///
/// Used to publish all available pre-keys for other users to initiate sessions.
pub struct AccountPreKeyBundle {
    /// Public identity key for DH operations.
    pub ik_public: X25519PublicKey,
    /// Public verification key for the identity.
    pub signing_key_public: VerifyingKey,
    /// Current signed pre-key with its ID.
    pub spk_public: (u32, X25519PublicKey),
    /// Signature for the signed pre-key.
    pub signature: Signature,
    /// All available one-time pre-keys.
    pub otpks_public: HashMap<u32, X25519PublicKey>,
}

/// A user account in the Signal Protocol ecosystem.
///
/// Manages identity keys, pre-keys, and established sessions. Provides methods
/// for creating and managing secure communication sessions with other users.
pub struct Account {
    pub(crate) ik: IdentityKey,
    pub(crate) spk_last_rotation: SystemTime,
    pub(crate) spk_store: SignedPreKeyStore,
    pub(crate) otpk_store: OneTimePreKeyStore,
    pub(crate) config: AccountConfig,
}

impl Account {
    /// Creates a new account with the given configuration.
    ///
    /// If no configuration is provided, default values are used.
    pub fn new(config: Option<AccountConfig>) -> Self {
        let config = config.unwrap_or_default();

        let ik = IdentityKey::new();
        let now = SystemTime::now();

        let spk_store = SignedPreKeyStore::new(config.max_spks);

        let mut otpk_store = OneTimePreKeyStore::new(config.max_otpks);
        otpk_store.generate_keys(config.max_otpks);

        Self {
            ik,
            spk_store,
            spk_last_rotation: now,
            otpk_store,
            config,
        }
    }

    /// Returns the complete pre-key bundle for this account.
    pub fn prekey_bundle(&self) -> AccountPreKeyBundle {
        let ik = &self.ik;
        let spk = self.spk();

        AccountPreKeyBundle {
            ik_public: ik.dh_key_public(),
            signing_key_public: ik.signing_key_public(),
            spk_public: (spk.id(), spk.public_key()),
            signature: spk.signature(&ik),
            otpks_public: self.otpk_store.public_keys(),
        }
    }

    /// Returns the current signed pre-key.
    pub(crate) fn spk(&self) -> &SignedPreKey {
        self.spk_store.get_current()
    }

    /// Returns the configuration for this account.
    pub fn config(&self) -> &AccountConfig {
        &self.config
    }

    /// Returns the X25519 public key component of this account's identity key.
    #[inline]
    pub fn ik_public(&self) -> X25519PublicKey {
        self.ik.dh_key_public()
    }

    /// Initiates a new session with another user.
    ///
    /// Implements the initiator's (Alice's) side of the X3DH protocol using
    /// the other user's pre-key bundle.
    pub fn create_outbound_session(
        &self,
        bob_x3dh_public_keys: &X3DHPublicKeys,
    ) -> Result<Session, Error> {
        let x3dh_result = X3DH::new(&self.config.protocol_info)
            .initiate_for_alice(&self.ik, bob_x3dh_public_keys)?;

        let session_id =
            self.derive_session_id(&bob_x3dh_public_keys.ik_public(), &x3dh_result.public_key());

        let x3dh_pub_key = x3dh_result.public_key();
        let ratchet = DoubleRatchet::initialize_for_alice(
            x3dh_result.shared_secret(),
            &bob_x3dh_public_keys.spk_public().1,
            self.config.max_skipped_messages,
        );

        let session = Session::new(
            session_id,
            ratchet,
            Some(OutboundSessionX3DHKeys {
                spk_id: bob_x3dh_public_keys.spk_public().0,
                ephemeral_key_public: x3dh_pub_key,
                otpk_id: bob_x3dh_public_keys.otpk_public().map(|(id, _)| id),
            }),
        );

        Ok(session)
    }

    /// Processes an incoming session initiation from another user.
    ///
    /// Implements the responder's (Bob's) side of the X3DH protocol using
    /// the initiator's identity and ephemeral keys.
    pub fn create_inbound_session(
        &mut self,
        alice_ik_public: &X25519PublicKey,
        outbound_session_x3dhkeys: &OutboundSessionX3DHKeys,
    ) -> Result<Session, Error> {
        let spk = if let Some(spk) = self.spk_store.get(outbound_session_x3dhkeys.spk_id) {
            spk
        } else {
            return Err(Error::PreKey("Invalid signed pre-key ID".to_string()));
        };

        let otpk = if let Some(id) = outbound_session_x3dhkeys.otpk_id {
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
            &outbound_session_x3dhkeys.ephemeral_key_public,
        )?;

        let ratchet = DoubleRatchet::initialize_for_bob(
            shared_secret,
            spk.key_pair(),
            self.config.max_skipped_messages,
        );
        let session_id = self.derive_session_id(
            alice_ik_public,
            &outbound_session_x3dhkeys.ephemeral_key_public,
        );
        let session = Session::new(session_id, ratchet, None);

        Ok(session)
    }

    /// Rotates the signed pre-key if the rotation interval has passed.
    pub fn rotate_spk(&mut self) -> Option<(u32, X25519PublicKey, Signature)> {
        let now = SystemTime::now();
        if now
            .duration_since(self.spk_last_rotation)
            .unwrap_or_default()
            >= self.config.spk_rotation_interval
        {
            let (id, spk) = self.spk_store.renew_key();
            self.spk_last_rotation = now;

            Some((id, spk.public_key(), spk.signature(&self.ik)))
        } else {
            None
        }
    }

    /// Replenishes one-time pre-keys to maintain the desired pool size.
    pub fn replenish_otpks(&mut self) -> HashMap<u32, X25519PublicKey> {
        self.otpk_store.replenish()
    }

    /// Derives a unique session ID from identity and ephemeral keys.
    ///
    /// Uses SHA256 hash of the identity keys, ephemeral key, and additional
    /// randomness to prevent collisions.
    fn derive_session_id(
        &self,
        their_dh_public: &X25519PublicKey,
        ephemeral_key_public: &X25519PublicKey,
    ) -> String {
        let mut hasher = Sha256::new();

        // Include both identities and the ephemeral key
        hasher.update(self.ik.dh_key_public().as_bytes());
        hasher.update(their_dh_public.as_bytes());
        hasher.update(ephemeral_key_public.as_bytes());

        let bytes = hasher.finalize();
        let engine = base64::engine::general_purpose::STANDARD;

        engine.encode(bytes)
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

impl Zeroize for Account {
    fn zeroize(&mut self) {
        self.ik.zeroize();
        self.spk_store.zeroize();
        self.otpk_store.zeroize();
    }
}

impl ZeroizeOnDrop for Account {}

#[cfg(test)]
mod tests {
    use crate::AccountConfig;
    use crate::{Account, X3DHPublicKeys};
    use std::time::Duration;

    #[test]
    fn test_account_key_bundle_generation() {
        let account = Account::new(None);

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

        let mut account = Account::new(Some(config));

        let initial_bundle = account.prekey_bundle();
        let initial_spk_id = initial_bundle.spk_public.0;

        std::thread::sleep(Duration::from_millis(10));

        let (new_spk_id, _, _) = account.rotate_spk().unwrap();

        assert_ne!(
            initial_spk_id, new_spk_id,
            "Signed pre-key should have been rotated"
        );
    }
}

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
            signature: spk.signature(ik),
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

        let session_id = Self::derive_session_id(
            &self.ik_public(),
            &bob_x3dh_public_keys.ik_public(),
            &x3dh_result.public_key(),
        );

        let x3dh_pub_key = x3dh_result.public_key();
        let ad = Self::derive_session_ad(&self.ik_public(), &bob_x3dh_public_keys.ik_public);

        let ratchet = DoubleRatchet::initialize_for_alice(
            x3dh_result.shared_secret(),
            &bob_x3dh_public_keys.spk_public().1,
            self.config.max_skipped_messages,
            ad,
        );

        let session = Session::new(
            session_id,
            bob_x3dh_public_keys.ik_public,
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
    ///
    /// # Account mutation
    ///
    /// This takes `&mut self` because it **irreversibly consumes account
    /// state**: if the initiator's keys reference a one-time pre-key
    /// ([`OutboundSessionX3DHKeys::otpk_id`] is `Some`), that key is removed
    /// from this account and can never be used again. This one-shot consumption
    /// is what gives the initial message its forward secrecy. (If `otpk_id` is
    /// `None`, no one-time pre-key is consumed.)
    ///
    /// The pre-key is consumed only when this call returns `Ok`. If it returns
    /// `Err`, the account is left unchanged, so the same initiation message can
    /// be retried against the same pre-key.
    ///
    /// # Persistence contract
    ///
    /// The returned [`Session`] and this now-mutated [`Account`] **must be
    /// persisted together atomically** — in a single transaction. They are two
    /// halves of one state transition; committing one without the other leaves
    /// the two stores diverged, and both outcomes are unrecoverable:
    ///
    /// - **Account committed, session lost:** the one-time pre-key is durably
    ///   gone but no session exists. The initiator's retries re-send the same
    ///   `otpk_id`, so every retry fails here with
    ///   [`Error::PreKey`]`("One-time pre-key not found")` — permanently. The
    ///   sender is stranded, and the session cannot be re-derived because the
    ///   consumed key material no longer exists.
    /// - **Session committed, account lost:** the one-time pre-key survives in
    ///   the durable account and can be consumed a second time, enabling
    ///   one-time-pre-key reuse and weakening forward secrecy.
    /// # Errors
    ///
    /// Returns [`Error::PreKey`] if the referenced signed pre-key id or
    /// one-time pre-key id is not present in this account.
    pub fn create_inbound_session(
        &mut self,
        alice_ik_public: X25519PublicKey,
        outbound_session_x3dh_keys: &OutboundSessionX3DHKeys,
    ) -> Result<Session, Error> {
        let spk = if let Some(spk) = self.spk_store.get(outbound_session_x3dh_keys.spk_id) {
            spk
        } else {
            return Err(Error::PreKey("Invalid signed pre-key Id".to_string()));
        };

        let otpk = if let Some(id) = outbound_session_x3dh_keys.otpk_id {
            Some(
                self.otpk_store
                    .take(id)
                    .ok_or_else(|| Error::PreKey("One-time pre-key not found".to_string()))?,
            )
        } else {
            None
        };

        let ad = Self::derive_session_ad(&alice_ik_public, &self.ik_public());

        let shared_secret = match X3DH::new(&self.config.protocol_info).initiate_for_bob(
            &self.ik,
            spk,
            otpk.clone(),
            &alice_ik_public,
            &outbound_session_x3dh_keys.ephemeral_key_public,
        ) {
            Ok(shared_secret) => shared_secret,
            Err(err) => {
                if let Some(otpk) = otpk {
                    self.otpk_store.insert(otpk);
                }
                return Err(err);
            }
        };

        let ratchet = DoubleRatchet::initialize_for_bob(
            shared_secret,
            spk.key_pair(),
            self.config.max_skipped_messages,
            ad,
        );
        let session_id = Self::derive_session_id(
            &alice_ik_public,
            &self.ik_public(),
            &outbound_session_x3dh_keys.ephemeral_key_public,
        );
        let session = Session::new(session_id, alice_ik_public, ratchet, None);

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
    /// Uses SHA256 hash of the identity keys, ephemeral key.
    pub fn derive_session_id(
        initiator_ik: &X25519PublicKey,
        responder_ik: &X25519PublicKey,
        ephemeral_key_public: &X25519PublicKey,
    ) -> String {
        let mut hasher = Sha256::new();

        hasher.update(initiator_ik.as_bytes());
        hasher.update(responder_ik.as_bytes());
        hasher.update(ephemeral_key_public.as_bytes());

        let bytes = hasher.finalize();
        let engine = base64::engine::general_purpose::STANDARD;

        engine.encode(bytes)
    }

    fn derive_session_ad(
        initiator_ik: &X25519PublicKey,
        responder_ik: &X25519PublicKey,
    ) -> Box<[u8; 64]> {
        let mut temp = Vec::with_capacity(64);
        temp.extend_from_slice(initiator_ik.as_bytes());
        temp.extend_from_slice(responder_ik.as_bytes());

        let mut ad = Box::new([0u8; 64]);
        ad.copy_from_slice(&temp);

        ad
    }
}

impl Zeroize for Account {
    fn zeroize(&mut self) {
        self.ik.zeroize();
        self.spk_store.zeroize();
        self.otpk_store.zeroize();
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Account {}

#[cfg(test)]
mod tests {
    use crate::AccountConfig;
    use crate::{Account, X3DHPublicKeys};
    use std::time::Duration;

    fn create_test_pkb_with_otpk(account: &Account) -> (X3DHPublicKeys, u32) {
        let pkb = account.prekey_bundle();
        let (otpk_id, otpk_pub) = {
            let (id, pk) = pkb.otpks_public.iter().next().unwrap();
            (*id, *pk)
        };
        let public = X3DHPublicKeys::try_from(
            pkb.ik_public.to_bytes(),
            pkb.signing_key_public.to_bytes(),
            (pkb.spk_public.0, pkb.spk_public.1.to_bytes()),
            pkb.signature.to_bytes(),
            Some((otpk_id, otpk_pub.to_bytes())),
        )
        .unwrap();
        (public, otpk_id)
    }

    fn create_test_pkb_without_otpk(account: &Account) -> X3DHPublicKeys {
        let pkb = account.prekey_bundle();
        X3DHPublicKeys::try_from(
            pkb.ik_public.to_bytes(),
            pkb.signing_key_public.to_bytes(),
            (pkb.spk_public.0, pkb.spk_public.1.to_bytes()),
            pkb.signature.to_bytes(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_account_pkb_generation() {
        let a = Account::new(None);

        let a_bundle = a.prekey_bundle();
        let (pkb, _) = create_test_pkb_with_otpk(&a);

        assert!(pkb.verify().is_ok(), "pkb should have valid signature");

        assert!(
            !a_bundle.otpks_public.is_empty(),
            "otpks should have been generated"
        );
    }

    #[test]
    fn test_spk_key_rotation() {
        let config = AccountConfig {
            spk_rotation_interval: Duration::from_millis(1),
            ..AccountConfig::default()
        };

        let mut account = Account::new(Some(config));

        let pkb = account.prekey_bundle();
        let spk_id_1 = pkb.spk_public.0;

        std::thread::sleep(Duration::from_millis(10));

        let (spk_id_2, _, _) = account.rotate_spk().unwrap();

        assert_ne!(spk_id_1, spk_id_2, "spk should have been rotated");
    }

    #[test]
    fn test_session_consistency_and_identity_binding() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        let (b_pkb, _) = create_test_pkb_with_otpk(&b_acc);

        let a_ses = a_acc.create_outbound_session(&b_pkb).unwrap();
        let a_ik = a_acc.ik_public();

        let x3dh_msg = a_ses.x3dh_keys().expect("a should have X3DH keys");

        let b_ses = b_acc.create_inbound_session(a_ik, &x3dh_msg).unwrap();

        assert_eq!(
            a_ses.session_id(),
            b_ses.session_id(),
            "session id mismatch"
        );
        println!("session id: {}", a_ses.session_id());

        assert_eq!(
            a_ses.ratchet.state.ad, b_ses.ratchet.state.ad,
            "associated-data (AD) mismatch"
        );

        let a_bytes = a_acc.ik_public().to_bytes();
        let b_bytes = b_acc.ik_public().to_bytes();

        let ad = &a_ses.ratchet.state.ad;
        assert_eq!(&ad[0..32], &a_bytes, "ad first half should be for a");
        assert_eq!(&ad[32..64], &b_bytes, "ad second half should be for b");
    }

    #[test]
    fn test_inbound_session_success_consumes_otpk() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        let (b_pkb, otpk_id) = create_test_pkb_with_otpk(&b_acc);
        let a_ses = a_acc.create_outbound_session(&b_pkb).unwrap();
        let x3dh_keys = a_ses.x3dh_keys().unwrap();

        assert_eq!(x3dh_keys.otpk_id, Some(otpk_id));

        let otpk_count = b_acc.otpk_store.count();
        let mut b_sess = b_acc
            .create_inbound_session(a_acc.ik_public(), &x3dh_keys)
            .unwrap();

        assert_eq!(b_acc.otpk_store.count(), otpk_count - 1);
        assert!(!b_acc.otpk_store.keys.contains_key(&otpk_id));

        let mut a_ses = a_ses;
        let message = a_ses.encrypt(b"hello, world!").unwrap();
        assert_eq!(b_sess.decrypt(&message).unwrap(), b"hello, world!");
    }

    #[test]
    fn test_inbound_session_failure_preserves_otpk() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        let (b_pkb, otpk_id) = create_test_pkb_with_otpk(&b_acc);
        let a_ses = a_acc.create_outbound_session(&b_pkb).unwrap();
        let x3dh_keys = a_ses.x3dh_keys().unwrap();

        // Force the key agreement to fail after the otpk is read
        b_acc
            .otpk_store
            .keys
            .get_mut(&otpk_id)
            .unwrap()
            .mark_as_used();
        let otpk_count = b_acc.otpk_store.count();

        let result = b_acc.create_inbound_session(a_acc.ik_public(), &x3dh_keys);
        assert!(result.is_err());

        assert_eq!(b_acc.otpk_store.count(), otpk_count);
        assert!(b_acc.otpk_store.keys.contains_key(&otpk_id));
    }

    #[test]
    fn test_session_still_works_when_pool_is_exhausted() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        // A server that has run out of one-time pre-keys for Bob.
        let b_pkb = create_test_pkb_without_otpk(&b_acc);
        assert!(b_pkb.otpk_public().is_none());

        let mut a_ses = a_acc.create_outbound_session(&b_pkb).unwrap();
        let x3dh_keys = a_ses.x3dh_keys().unwrap();
        assert_eq!(x3dh_keys.otpk_id, None);

        // X3DH without DH4 is permitted, so this must still establish.
        let mut b_ses = b_acc
            .create_inbound_session(a_acc.ik_public(), &x3dh_keys)
            .unwrap();
        let message = a_ses.encrypt(b"hello, world!").unwrap();
        assert_eq!(b_ses.decrypt(&message).unwrap(), b"hello, world!");
    }

    #[test]
    fn test_otpk_cannot_be_claimed_twice() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        let (b_pkb, _) = create_test_pkb_with_otpk(&b_acc);
        let a_ses = a_acc.create_outbound_session(&b_pkb).unwrap();
        let x3dh_keys = a_ses.x3dh_keys().unwrap();

        assert!(x3dh_keys.otpk_id.is_some());

        b_acc
            .create_inbound_session(a_acc.ik_public(), &x3dh_keys)
            .unwrap();

        assert!(
            b_acc
                .create_inbound_session(a_acc.ik_public(), &x3dh_keys)
                .is_err(),
            "a spent otpk must not be reusable"
        );
    }
}

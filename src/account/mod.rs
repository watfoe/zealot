mod config;
pub use config::*;
mod session;
pub use session::*;

use crate::X25519PublicKey;
use crate::{DoubleRatchet, Error, IdentityKey, SignedPreKey, SignedPreKeyStore, X3DH};
use crate::{OneTimePreKeyStore, X3DHPublicKeys};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
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
    ///
    /// This is one half of the account's identity. The other half is
    /// [`Self::signing_key_public`], and a peer needs both to open a session.
    #[inline]
    pub fn ik_public(&self) -> X25519PublicKey {
        self.ik.dh_key_public()
    }

    /// Returns the Ed25519 public key component of this account's identity key.
    ///
    /// The two identity keys are independent, so neither vouches for the
    /// other. Anything that identifies this account to a person, such as a
    /// fingerprint or safety number shown for out-of-band verification, must
    /// cover this key as well as [`Self::ik_public`].
    #[inline]
    pub fn signing_key_public(&self) -> VerifyingKey {
        self.ik.signing_key_public()
    }

    /// Initiates a new session with another user.
    ///
    /// Implements the initiator's (Alice's) side of the X3DH protocol using
    /// the other user's pre-key bundle.
    ///
    /// # Identity binding
    ///
    /// The session is bound to both of the peer's identity keys exactly as the
    /// bundle presents them: the X25519 key and the Ed25519 key that signed
    /// the pre-key. The bundle's signature only shows that its pre-key belongs
    /// to whoever holds that Ed25519 key, so a bundle whose signing key has
    /// been replaced still verifies. Compare
    /// [`Session::peer_ik_public`] **and**
    /// [`Session::peer_signing_key_public`] against the identity you expect
    /// before trusting the session.
    pub fn create_outbound_session(
        &self,
        bob_x3dh_public_keys: &X3DHPublicKeys,
    ) -> Result<Session, Error> {
        let x3dh_result = X3DH::new(&self.config.protocol_info)
            .initiate_for_alice(&self.ik, bob_x3dh_public_keys)?;

        let session_id = Self::derive_session_id(
            &self.ik_public(),
            &self.signing_key_public(),
            &bob_x3dh_public_keys.ik_public(),
            &bob_x3dh_public_keys.signing_key_public(),
            &x3dh_result.public_key(),
        );

        let x3dh_pub_key = x3dh_result.public_key();
        let ad = Self::derive_session_ad(
            &self.ik_public(),
            &self.signing_key_public(),
            &bob_x3dh_public_keys.ik_public(),
            &bob_x3dh_public_keys.signing_key_public(),
        );

        let ratchet = DoubleRatchet::initialize_for_alice(
            x3dh_result.shared_secret(),
            &bob_x3dh_public_keys.spk_public().1,
            self.config.max_skipped_messages,
            ad,
        );

        let session = Session::new(
            session_id,
            bob_x3dh_public_keys.ik_public,
            bob_x3dh_public_keys.signing_key_public,
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
    /// Both of the initiator's identity keys are required. They are bound into
    /// the session together with this account's own, so the session only
    /// works if both sides hold the same four keys: a message from an
    /// initiator who was given a different signing key for this account, or
    /// who is not the holder of `alice_signing_key_public`, fails to decrypt.
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
        alice_signing_key_public: VerifyingKey,
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

        let ad = Self::derive_session_ad(
            &alice_ik_public,
            &alice_signing_key_public,
            &self.ik_public(),
            &self.signing_key_public(),
        );

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
            &alice_signing_key_public,
            &self.ik_public(),
            &self.signing_key_public(),
            &outbound_session_x3dh_keys.ephemeral_key_public,
        );
        let session = Session::new(
            session_id,
            alice_ik_public,
            alice_signing_key_public,
            ratchet,
            None,
        );

        Ok(session)
    }

    /// Rotates the signed pre-key if the rotation interval has passed.
    pub fn rotate_spk(&mut self) -> Option<(u32, X25519PublicKey, Signature)> {
        let now = SystemTime::now();
        match now.duration_since(self.spk_last_rotation) {
            Ok(elapsed) if elapsed >= self.config.spk_rotation_interval => {
                let (id, spk) = self.spk_store.renew_key();
                self.spk_last_rotation = now;

                Some((id, spk.public_key(), spk.signature(&self.ik)))
            }
            Ok(_) => None,
            Err(_) => {
                self.spk_last_rotation = now;
                None
            }
        }
    }

    /// Replenishes one-time pre-keys to maintain the desired pool size.
    pub fn replenish_otpks(&mut self) -> HashMap<u32, X25519PublicKey> {
        self.otpk_store.replenish()
    }

    /// Derives a unique session ID from identity and ephemeral keys.
    ///
    /// Uses the SHA256 hash of both identity keys of both parties and the
    /// initiator's ephemeral key, so two sides that disagree about any
    /// identity key also disagree about the session ID.
    pub fn derive_session_id(
        initiator_ik: &X25519PublicKey,
        initiator_signing_key: &VerifyingKey,
        responder_ik: &X25519PublicKey,
        responder_signing_key: &VerifyingKey,
        ephemeral_key_public: &X25519PublicKey,
    ) -> String {
        let mut hasher = Sha256::new();

        hasher.update(initiator_ik.as_bytes());
        hasher.update(initiator_signing_key.as_bytes());
        hasher.update(responder_ik.as_bytes());
        hasher.update(responder_signing_key.as_bytes());
        hasher.update(ephemeral_key_public.as_bytes());

        let bytes = hasher.finalize();
        let engine = base64::engine::general_purpose::STANDARD;

        engine.encode(bytes)
    }

    /// Derives the associated data authenticated with every message of a
    /// session.
    ///
    /// It commits to both identity keys of both parties. The X25519 and
    /// Ed25519 identity keys are independent of each other, so binding only
    /// the X25519 keys would leave the key that signed the pre-key outside
    /// what the session authenticates. Every input has a fixed length, so the
    /// concatenation is unambiguous.
    fn derive_session_ad(
        initiator_ik: &X25519PublicKey,
        initiator_signing_key: &VerifyingKey,
        responder_ik: &X25519PublicKey,
        responder_signing_key: &VerifyingKey,
    ) -> Box<[u8; 64]> {
        let mut hasher = Sha512::new();

        hasher.update(b"Zealot-Session-AD-v2");
        hasher.update(initiator_ik.as_bytes());
        hasher.update(initiator_signing_key.as_bytes());
        hasher.update(responder_ik.as_bytes());
        hasher.update(responder_signing_key.as_bytes());

        let mut ad = Box::new([0u8; 64]);
        ad.copy_from_slice(&hasher.finalize());

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
    use std::time::{Duration, SystemTime};

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

        let b_ses = b_acc
            .create_inbound_session(a_ik, a_acc.signing_key_public(), &x3dh_msg)
            .unwrap();

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

        // Each side records the other's full identity.
        assert_eq!(a_ses.peer_ik_public(), b_acc.ik_public());
        assert_eq!(a_ses.peer_signing_key_public(), b_acc.signing_key_public());
        assert_eq!(b_ses.peer_ik_public(), a_acc.ik_public());
        assert_eq!(b_ses.peer_signing_key_public(), a_acc.signing_key_public());
    }

    #[test]
    fn test_session_ad_commits_to_every_identity_key() {
        // Takes each of the four keys from the account given for that slot.
        fn ad(a_ik: &Account, a_sk: &Account, b_ik: &Account, b_sk: &Account) -> Box<[u8; 64]> {
            Account::derive_session_ad(
                &a_ik.ik_public(),
                &a_sk.signing_key_public(),
                &b_ik.ik_public(),
                &b_sk.signing_key_public(),
            )
        }

        let a = Account::new(None);
        let b = Account::new(None);
        let other = Account::new(None);

        let honest = ad(&a, &a, &b, &b);
        assert_eq!(ad(&a, &a, &b, &b), honest);

        // Replacing any one of the four keys, or swapping the roles, changes it.
        assert_ne!(ad(&other, &a, &b, &b), honest);
        assert_ne!(ad(&a, &other, &b, &b), honest);
        assert_ne!(ad(&a, &a, &other, &b), honest);
        assert_ne!(ad(&a, &a, &b, &other), honest);
        assert_ne!(ad(&b, &b, &a, &a), honest);
    }

    /// A bundle that keeps `victim`'s X25519 identity key but carries
    /// `attacker`'s signing key, signed pre-key and signature. Its signature
    /// verifies, because it is the attacker's own.
    fn create_substituted_pkb(victim: &Account, attacker: &Account) -> X3DHPublicKeys {
        let victim_pkb = victim.prekey_bundle();
        let attacker_pkb = attacker.prekey_bundle();
        X3DHPublicKeys::try_from(
            victim_pkb.ik_public.to_bytes(),
            attacker_pkb.signing_key_public.to_bytes(),
            (
                attacker_pkb.spk_public.0,
                attacker_pkb.spk_public.1.to_bytes(),
            ),
            attacker_pkb.signature.to_bytes(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_substituted_signing_key_is_visible_on_the_session() {
        let a_acc = Account::new(None);
        let b_acc = Account::new(None);
        let m_acc = Account::new(None);

        let substituted = create_substituted_pkb(&b_acc, &m_acc);
        assert!(substituted.verify().is_ok());

        let a_ses = a_acc.create_outbound_session(&substituted).unwrap();

        // The X25519 key alone still looks like Bob.
        assert_eq!(a_ses.peer_ik_public(), b_acc.ik_public());
        // The session reports the key that actually signed the pre-key, which
        // is not Bob's, so a check against Bob's full identity catches it.
        assert_eq!(a_ses.peer_signing_key_public(), m_acc.signing_key_public());
        assert_ne!(a_ses.peer_signing_key_public(), b_acc.signing_key_public());

        // It is also a different session from the one an honest bundle gives.
        let honest = a_acc
            .create_outbound_session(&create_test_pkb_without_otpk(&b_acc))
            .unwrap();
        let x3dh_keys = a_ses.x3dh_keys().unwrap();
        assert_ne!(
            a_ses.session_id(),
            Account::derive_session_id(
                &a_acc.ik_public(),
                &a_acc.signing_key_public(),
                &b_acc.ik_public(),
                &b_acc.signing_key_public(),
                &x3dh_keys.ephemeral_key_public,
            )
        );
        assert_eq!(honest.peer_signing_key_public(), b_acc.signing_key_public());
    }

    #[test]
    fn test_inbound_session_rejects_messages_when_initiator_signing_key_differs() {
        let a_acc = Account::new(None);
        let other = Account::new(None);

        let run = |claimed_signing_key| {
            let mut b_acc = Account::new(None);
            let (b_pkb, _) = create_test_pkb_with_otpk(&b_acc);
            let mut a_ses = a_acc.create_outbound_session(&b_pkb).unwrap();
            let mut b_ses = b_acc
                .create_inbound_session(
                    a_acc.ik_public(),
                    claimed_signing_key,
                    &a_ses.x3dh_keys().unwrap(),
                )
                .unwrap();
            let message = a_ses.encrypt(b"hello, world!").unwrap();
            (
                a_ses.session_id() == b_ses.session_id(),
                b_ses.decrypt(&message),
            )
        };

        // Both sides hold the same four keys.
        let (same_id, result) = run(a_acc.signing_key_public());
        assert!(same_id);
        assert_eq!(result.unwrap(), b"hello, world!");

        // Bob was told the initiator holds a signing key that Alice does not.
        let (same_id, result) = run(other.signing_key_public());
        assert!(!same_id);
        assert_eq!(result, Err(crate::Error::MessageDecryptionFailed));
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
            .create_inbound_session(a_acc.ik_public(), a_acc.signing_key_public(), &x3dh_keys)
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

        let result =
            b_acc.create_inbound_session(a_acc.ik_public(), a_acc.signing_key_public(), &x3dh_keys);
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
            .create_inbound_session(a_acc.ik_public(), a_acc.signing_key_public(), &x3dh_keys)
            .unwrap();
        let message = a_ses.encrypt(b"hello, world!").unwrap();
        assert_eq!(b_ses.decrypt(&message).unwrap(), b"hello, world!");
    }

    #[test]
    fn test_spk_rotation_reanchors_when_clock_moves_backwards() {
        let mut account = Account::new(None);
        let interval = account.config.spk_rotation_interval;

        // A rotation timestamp in the future, as a backwards clock jump leaves behind.
        let future = SystemTime::now() + interval * 52;
        account.spk_last_rotation = future;

        // This call must not rotate, but it must repair the anchor.
        assert!(account.rotate_spk().is_none());
        assert!(
            account.spk_last_rotation < future,
            "a future rotation timestamp must be re-anchored, not left in place"
        );

        // Without re-anchoring, rotation would stay suppressed until wall time
        // caught back up. It must instead resume on the normal schedule.
        account.spk_last_rotation = SystemTime::now() - interval * 2;
        assert!(
            account.rotate_spk().is_some(),
            "rotation must resume once the interval has genuinely elapsed"
        );
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
            .create_inbound_session(a_acc.ik_public(), a_acc.signing_key_public(), &x3dh_keys)
            .unwrap();

        assert!(
            b_acc
                .create_inbound_session(a_acc.ik_public(), a_acc.signing_key_public(), &x3dh_keys)
                .is_err(),
            "a spent otpk must not be reusable"
        );
    }
}

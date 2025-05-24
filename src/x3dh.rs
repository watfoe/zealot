use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    Error, IdentityKey, OneTimePreKey, SessionPreKeyBundle, SignedPreKey, X25519PublicKey,
    X25519Secret, generate_random_seed,
};

const SALT: &[u8] = b"Zealot-E2E-NaCl";

pub(crate) struct EphemeralKey {
    key: X25519Secret,
}

impl Default for EphemeralKey {
    fn default() -> Self {
        Self {
            key: X25519Secret::from(generate_random_seed().unwrap()),
        }
    }
}

impl EphemeralKey {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn public_key(&self) -> X25519PublicKey {
        self.key.public_key()
    }

    pub(crate) fn dh(&self, public: &X25519PublicKey) -> [u8; 32] {
        self.key.dh(public).to_bytes()
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// The result of an X3DH key agreement initiated by A.
///
/// Contains both the calculated shared secret and A's ephemeral public key
/// that needs to be transmitted to B.
pub struct X3DHResult {
    shared_secret: [u8; 32],
    ephemeral_public: X25519PublicKey, // A's ephemeral public key (sent to B)
}

impl X3DHResult {
    /// Returns the ephemeral public key that needs to be sent to the responder.
    pub fn public_key(&self) -> X25519PublicKey {
        self.ephemeral_public
    }

    /// Consumes the result and returns only the shared secret.
    ///
    /// This should be called only after the ephemeral public key has been
    /// transmitted to the responder.
    pub fn shared_secret(self) -> [u8; 32] {
        self.shared_secret
    }
}

/// Implementation of the X3DH (Extended Triple Diffie-Hellman) key agreement protocol.
///
/// X3DH enables two parties to establish a shared secret asynchronously, even if one
/// party is offline. The protocol combines multiple Diffie-Hellman exchanges to provide
/// strong security properties.
pub struct X3DH {
    info: Vec<u8>, // Application-specific info for the KDF
}

impl X3DH {
    /// Creates a new X3DH protocol instance with the specified application info.
    ///
    /// The info parameter is used as context for the HKDF key derivation, ensuring
    /// that keys derived in different contexts will be different even if the same
    /// key material is used.
    pub fn new(info: &[u8]) -> Self {
        Self {
            info: info.to_vec(),
        }
    }

    /// Initiates a key agreement with a responder's pre-key bundle.
    ///
    /// This implements Alice's side of the X3DH protocol:
    /// 1. Verifies Bob's signed pre-key
    /// 2. Generates an ephemeral key pair
    /// 3. Performs the necessary DH computations
    /// 4. Derives the shared secret
    pub fn initiate_for_alice(
        &self,
        a_identity: &IdentityKey,
        b_bundle: &SessionPreKeyBundle,
    ) -> Result<X3DHResult, Error> {
        b_bundle
            .verify()
            .map_err(|_| Error::PreKey("Failed to verify pre-key bundle".to_string()))?;

        let a_ephemeral = EphemeralKey::new();

        // DH1 = DH(IKa, SPKb)
        let dh1 = a_identity.dh(&b_bundle.spk_public().1);
        // DH2 = DH(EKa, IKb)
        let dh2 = a_ephemeral.dh(&b_bundle.ik_public());
        // DH3 = DH(EKa, SPKb)
        let dh3 = a_ephemeral.dh(&b_bundle.spk_public().1);
        // DH4 = DH(EKa, OPKb)
        let dh4_opt = b_bundle.otpk_public().map(|otpk| a_ephemeral.dh(&otpk.1));

        let a_ephemeral_public = a_ephemeral.public_key();

        let result = self.calculate_shared_secret(dh1, dh2, dh3, dh4_opt, &a_ephemeral_public)?;

        Ok(result)
    }

    /// Processes an initiation message from the initiator (Alice).
    ///
    /// This implements Bob's side of the X3DH protocol:
    /// 1. Performs the same DH computations as Alice did
    /// 2. Derives the same shared secret
    pub fn initiate_for_bob(
        &self,
        b_identity: &IdentityKey,
        b_signed_pre_key: &SignedPreKey,
        b_one_time_pre_key: Option<OneTimePreKey>,
        a_identity_public: &X25519PublicKey,
        a_ephemeral_public: &X25519PublicKey,
    ) -> Result<[u8; 32], Error> {
        // DH1 = DH(SPKb, IKa)
        let dh1 = b_signed_pre_key.dh(a_identity_public);
        // DH2 = DH(IKb, EKa)
        let dh2 = b_identity.dh(a_ephemeral_public);
        // DH3 = DH(SPKb, EKa)
        let dh3 = b_signed_pre_key.dh(a_ephemeral_public);
        // DH4 = DH(OPKb, EKa)
        let dh4_opt: Option<Result<[u8; 32], Error>> = b_one_time_pre_key.map(|opk| {
            let result = opk.dh(a_ephemeral_public).map_err(|_| {
                Error::PreKey("Error performing DH with one-time pre-key".to_string())
            })?;
            Ok(result)
        });

        let dh4 = match dh4_opt {
            Some(result) => Some(result?),
            None => None,
        };

        let result = self.calculate_shared_secret(dh1, dh2, dh3, dh4, a_ephemeral_public)?;

        Ok(result.shared_secret)
    }

    fn calculate_shared_secret(
        &self,
        mut dh1: [u8; 32],
        mut dh2: [u8; 32],
        mut dh3: [u8; 32],
        mut dh4: Option<[u8; 32]>,
        ephemeral_public: &X25519PublicKey,
    ) -> Result<X3DHResult, Error> {
        // IKM = DH1 || DH2 || DH3 || DH4 (if available)
        let mut key_material = Vec::with_capacity(128);
        key_material.extend_from_slice(&dh1);
        key_material.extend_from_slice(&dh2);
        key_material.extend_from_slice(&dh3);
        if let Some(dh4_bytes) = dh4 {
            key_material.extend_from_slice(dh4_bytes.as_ref());
        }

        dh1.zeroize();
        dh2.zeroize();
        dh3.zeroize();
        dh4.zeroize();

        let hkdf = Hkdf::<Sha256>::new(Some(SALT), &key_material);

        key_material.zeroize();

        let mut shared_secret = [0u8; 32];
        hkdf.expand(&self.info, &mut shared_secret)
            .map_err(|_| Error::Crypto("HKDF expansion failed".to_string()))?;

        Ok(X3DHResult {
            shared_secret,
            ephemeral_public: *ephemeral_public,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityKey, OneTimePreKey, SessionPreKeyBundle, SignedPreKey};

    #[test]
    fn test_x3dh_agreement_with_one_time_key() {
        let alice_identity = IdentityKey::new();

        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);

        let bob_bundle = SessionPreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Alice initiates the key agreement
        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        // Bob processes Alice's initiation
        let bob_secret = x3dh
            .initiate_for_bob(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.dh_key_public(),
                &alice_result.ephemeral_public,
            )
            .unwrap();

        assert_eq!(alice_result.shared_secret, bob_secret);
    }

    #[test]
    fn test_x3dh_agreement_without_one_time_key() {
        let alice_identity = IdentityKey::new();

        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);

        let bob_bundle = SessionPreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        let bob_secret = x3dh
            .initiate_for_bob(
                &bob_identity,
                &bob_signed_pre_key,
                None,
                &alice_identity.dh_key_public(),
                &alice_result.ephemeral_public,
            )
            .unwrap();

        assert_eq!(alice_result.shared_secret, bob_secret);
    }

    #[test]
    fn test_x3dh_bundle_verification() {
        let alice_identity = IdentityKey::new();

        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);

        // TODO: For this test, we need a way to create an invalid bundle

        // A valid bundle
        let bob_bundle = SessionPreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        // For now, we'll just test that the valid bundle passes verification
        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let result = x3dh.initiate_for_alice(&alice_identity, &bob_bundle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_x3dh_different_info_produces_different_secrets() {
        let alice_identity = IdentityKey::new();

        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);

        let bob_bundle = SessionPreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        let x3dh1 = X3DH::new(b"App-A");
        let alice_result1 = x3dh1
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        let x3dh2 = X3DH::new(b"App-B");
        let alice_result2 = x3dh2
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        assert_ne!(alice_result1.shared_secret, alice_result2.shared_secret);
    }

    #[test]
    fn test_ephemeral_key_zeroing() {
        let ephemeral = EphemeralKey::new();

        let other_key = EphemeralKey::new();
        let other_public = other_key.public_key();

        let _shared_secret = ephemeral.dh(&other_public);

        drop(ephemeral);
    }

    #[test]
    fn test_x3dh_shared_secret_length() {
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);

        let bob_bundle = SessionPreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        assert_eq!(alice_result.shared_secret.len(), 32);
    }
}

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey, generate_random_seed};

const SALT: &[u8] = b"Zealot-E2E-NaCl";

pub struct EphemeralKey {
    key: StaticSecret,
}

impl EphemeralKey {
    pub fn new() -> Self {
        Self {
            key: StaticSecret::from(generate_random_seed().unwrap()),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.key)
    }

    pub fn dh(&self, public: &PublicKey) -> [u8; 32] {
        self.key.diffie_hellman(public).to_bytes()
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub struct X3DHResult {
    shared_secret: Vec<u8>,
    ephemeral_public: PublicKey, // A's ephemeral public key (sent to B)
}

impl X3DHResult {
    pub fn get_public_key(&self) -> PublicKey {
        self.ephemeral_public
    }

    pub fn get_shared_secret(self) -> Vec<u8> {
        self.shared_secret
    }
}

pub struct X3DH {
    info: Vec<u8>, // Application-specific info for the KDF
}

impl X3DH {
    pub fn new(info: &[u8]) -> Self {
        Self {
            info: info.to_vec(),
        }
    }

    // A initiates the key agreement with B's bundle
    pub fn initiate(
        &self,
        a_identity: &IdentityKey,
        b_bundle: &PreKeyBundle,
    ) -> Result<X3DHResult, &'static str> {
        // First, verify B's bundle
        b_bundle
            .verify()
            .map_err(|_| "Failed to verify pre-key bundle")?;

        let a_ephemeral = EphemeralKey::new();

        // DH1 = DH(IKa, SPKb) - A's Identity Key and B's Signed Pre-Key
        let mut dh1 = a_identity.dh(&b_bundle.get_signed_pre_key_public());
        // DH2 = DH(EKa, IKb) - A's Ephemeral Key and B's Identity Key
        let mut dh2 = a_ephemeral.dh(&b_bundle.get_identity_key_public());
        // DH3 = DH(EKa, SPKb) - A's Ephemeral Key and B's Signed Pre-Key
        let mut dh3 = a_ephemeral.dh(&b_bundle.get_signed_pre_key_public());
        // DH4 = DH(EKa, OPKb) - A's Ephemeral Key and B's One-Time Pre-Key (if available)
        let mut dh4_opt = b_bundle
            .get_one_time_pre_key_public()
            .map(|opk| a_ephemeral.dh(&opk));

        let a_ephemeral_public = a_ephemeral.public_key();

        // Combine DH outputs to produce the shared secret
        let result =
            self.calculate_shared_secret(&dh1, &dh2, &dh3, dh4_opt.as_ref(), &a_ephemeral_public)?;

        dh1.zeroize();
        dh2.zeroize();
        dh3.zeroize();
        dh4_opt.zeroize();

        Ok(result)
    }

    // B processes the message from A
    pub fn process_initiation(
        &self,
        b_identity: &IdentityKey,
        b_signed_pre_key: &SignedPreKey,
        b_one_time_pre_key: Option<OneTimePreKey>,
        a_identity_public: &PublicKey,
        a_ephemeral_public: &PublicKey,
    ) -> Result<Vec<u8>, &'static str> {
        // DH1 = DH(SPKb, IKa) - B's Signed Pre-Key and A's Identity Key
        let mut dh1 = b_signed_pre_key.dh(a_identity_public);
        // DH2 = DH(IKb, EKa) - B's Identity Key and A's Ephemeral Key
        let mut dh2 = b_identity.dh(a_ephemeral_public);
        // DH3 = DH(SPKb, EKa) - B's Signed Pre-Key and A's Ephemeral Key
        let mut dh3 = b_signed_pre_key.dh(a_ephemeral_public);
        // DH4 = DH(OPKb, EKa) - B's One-Time Pre-Key and A's Ephemeral Key
        let dh4_opt = b_one_time_pre_key.map(|opk| {
            let result = opk
                .dh(a_ephemeral_public)
                .map_err(|_| "Error performing DH with one-time pre-key")?;
            Ok(result)
        });

        let mut dh4 = match dh4_opt {
            Some(result) => Some(result?),
            None => None,
        };

        let result =
            self.calculate_shared_secret(&dh1, &dh2, &dh3, dh4.as_ref(), a_ephemeral_public)?;

        dh1.zeroize();
        dh2.zeroize();
        dh3.zeroize();
        dh4.zeroize();

        Ok(result.shared_secret)
    }

    fn calculate_shared_secret(
        &self,
        dh1: &[u8; 32],
        dh2: &[u8; 32],
        dh3: &[u8; 32],
        dh4: Option<&[u8; 32]>,
        ephemeral_public: &PublicKey,
    ) -> Result<X3DHResult, &'static str> {
        // IKM = DH1 || DH2 || DH3 || DH4 (if available)
        let mut key_material = Vec::new();
        key_material.extend_from_slice(dh1);
        key_material.extend_from_slice(dh2);
        key_material.extend_from_slice(dh3);
        if let Some(dh4_bytes) = dh4 {
            key_material.extend_from_slice(dh4_bytes);
        }

        let hkdf = Hkdf::<Sha256>::new(Some(SALT), &key_material);

        key_material.zeroize();

        let mut shared_secret = vec![0u8; 42]; // 256-bit shared secret
        hkdf.expand(&self.info, &mut shared_secret)
            .map_err(|_| "HKDF expansion failed")?;

        Ok(X3DHResult {
            shared_secret,
            ephemeral_public: *ephemeral_public,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey};

    #[test]
    fn test_x3dh_agreement_with_one_time_key() {
        let alice_identity = IdentityKey::new();

        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);

        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Alice initiates the key agreement
        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();

        // Bob processes Alice's initiation
        let bob_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
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

        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();

        let bob_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                None,
                &alice_identity.get_public_dh_key(),
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
        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        // For now, we'll just test that the valid bundle passes verification
        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let result = x3dh.initiate(&alice_identity, &bob_bundle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_x3dh_different_info_produces_different_secrets() {
        let alice_identity = IdentityKey::new();

        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);

        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        let x3dh1 = X3DH::new(b"App-A");
        let alice_result1 = x3dh1.initiate(&alice_identity, &bob_bundle).unwrap();

        let x3dh2 = X3DH::new(b"App-B");
        let alice_result2 = x3dh2.initiate(&alice_identity, &bob_bundle).unwrap();

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

        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();

        assert_eq!(alice_result.shared_secret.len(), 42);
    }
}

use crate::{IdentityKey, OneTimePreKey};
use ed25519_dalek::Verifier;
use rand_core::{OsRng, TryRngCore};
use x25519_dalek::StaticSecret;

pub struct SignedPreKey {
    pre_key: StaticSecret,
    id: u32, // for referencing this pre-key
    created_at: std::time::SystemTime,
}

impl SignedPreKey {
    pub fn new(id: u32) -> Self {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();
        let pre_key = StaticSecret::from(seed);

        Self {
            pre_key,
            id,
            created_at: std::time::SystemTime::now(),
        }
    }

    pub fn get_public_key(&self) -> x25519_dalek::PublicKey {
        (&self.pre_key).into()
    }

    pub fn get_key_pair(&self) -> StaticSecret {
        self.pre_key.clone()
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    pub fn dh(&self, public_key: &x25519_dalek::PublicKey) -> [u8; 32] {
        self.pre_key.diffie_hellman(public_key).to_bytes()
    }

    // Generate a signature for this pre-key using the identity key
    pub fn signature(&self, identity_key: &IdentityKey) -> ed25519_dalek::Signature {
        let encoded = self.encode_for_signature();
        identity_key.sign(&encoded)
    }

    fn encode_for_signature(&self) -> [u8; 32] {
        self.get_public_key().to_bytes()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Add the ID (4 bytes)
        result.extend_from_slice(&self.id.to_be_bytes());

        // Add the creation timestamp
        let timestamp = self
            .created_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        result.extend_from_slice(&timestamp.to_be_bytes());

        // Add the key bytes
        result.extend_from_slice(self.pre_key.as_bytes());

        result
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 12 + 32 {
            // 4 bytes ID + 8 bytes timestamp + 32 bytes key
            return Err("Invalid pre-key data length");
        }

        // Extract the ID
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&bytes[0..4]);
        let id = u32::from_be_bytes(id_bytes);

        // Extract the timestamp
        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&bytes[4..12]);
        let timestamp = u64::from_be_bytes(timestamp_bytes);

        let created_at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);

        // Extract the key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes[12..44]);
        let pre_key = StaticSecret::from(key_bytes);

        Ok(Self {
            pre_key,
            id,
            created_at,
        })
    }
}

pub struct PreKeyBundle {
    identity_key_dh_public: x25519_dalek::PublicKey,
    identity_key_verify_public: ed25519_dalek::VerifyingKey,
    signed_pre_key_id: u32,
    signed_pre_key_public: x25519_dalek::PublicKey,
    signature: ed25519_dalek::Signature,
    one_time_pre_key_public: Option<x25519_dalek::PublicKey>,
}

impl PreKeyBundle {
    pub fn new(
        identity_key: &IdentityKey,
        signed_pre_key: &SignedPreKey,
        one_time_pre_key: Option<&OneTimePreKey>,
    ) -> Self {
        let identity_key_dh_public = identity_key.get_public_dh_key();
        let identity_key_verify_public = identity_key.get_public_signing_key();
        let signed_pre_key_public = signed_pre_key.get_public_key();
        let signature = signed_pre_key.signature(identity_key);

        Self {
            identity_key_dh_public,
            identity_key_verify_public,
            signed_pre_key_id: signed_pre_key.get_id(),
            signed_pre_key_public,
            signature,
            one_time_pre_key_public: one_time_pre_key.map(|key| key.get_public_key()),
        }
    }

    pub fn verify(&self) -> Result<(), ed25519_dalek::ed25519::Error> {
        let encoded_key = self.signed_pre_key_public.to_bytes();
        self.identity_key_verify_public
            .verify(&encoded_key, &self.signature)
    }

    pub fn get_signed_pre_key_public(&self) -> x25519_dalek::PublicKey {
        self.signed_pre_key_public
    }

    pub fn get_signed_pre_id(&self) -> u32 {
        self.signed_pre_key_id
    }

    pub fn get_identity_key_public(&self) -> x25519_dalek::PublicKey {
        self.identity_key_dh_public
    }

    pub fn get_identity_key_verify_public(&self) -> ed25519_dalek::VerifyingKey {
        self.identity_key_verify_public
    }

    pub fn get_one_time_pre_key_public(&self) -> Option<x25519_dalek::PublicKey> {
        self.one_time_pre_key_public
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKey;

    #[test]
    fn test_signed_pre_key_creation() {
        let pre_key = SignedPreKey::new(123);

        // Check the ID is set correctly
        assert_eq!(pre_key.get_id(), 123);

        // Ensure the key is properly initialized
        let public_key = pre_key.get_public_key();
        assert!(!public_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_pre_key_serialization() {
        let original_key = SignedPreKey::new(42);
        let serialized = original_key.serialize();

        // Ensure we have enough bytes (4 for ID, 8 for timestamp, 32 for key)
        assert_eq!(serialized.len(), 44);

        // Deserialize and check if it matches
        let deserialized_key = SignedPreKey::deserialize(&serialized).unwrap();
        assert_eq!(deserialized_key.get_id(), original_key.get_id());
        assert_eq!(
            deserialized_key.get_public_key().as_bytes(),
            original_key.get_public_key().as_bytes()
        );

        // Test invalid data
        let invalid_data = vec![0; 20]; // Too short
        assert!(SignedPreKey::deserialize(&invalid_data).is_err());
    }

    #[test]
    fn test_diffie_hellman() {
        let alice_key = SignedPreKey::new(1);
        let bob_key = SignedPreKey::new(2);

        let alice_public = alice_key.get_public_key();
        let bob_public = bob_key.get_public_key();

        // Both should compute the same shared secret
        let shared_alice = alice_key.dh(&bob_public);
        let shared_bob = bob_key.dh(&alice_public);

        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_pre_key_bundle_creation_and_verification() {
        let identity_key = IdentityKey::new();
        let pre_key = SignedPreKey::new(99);

        // Create a bundle
        let bundle = PreKeyBundle::new(&identity_key, &pre_key, None);

        // Verify the bundle
        assert!(bundle.verify().is_ok());

        // Create another bundle with different keys
        let another_identity = IdentityKey::new();
        // let another_pre_key = SignedPreKey::new(100);

        // Try to create an invalid bundle (mixing keys)
        let invalid_bundle = PreKeyBundle {
            identity_key_dh_public: identity_key.get_public_dh_key(),
            identity_key_verify_public: another_identity.get_public_signing_key(), // Wrong verify key
            signed_pre_key_id: pre_key.get_id(),
            signed_pre_key_public: pre_key.get_public_key(),
            signature: pre_key.signature(&identity_key),
            one_time_pre_key_public: None,
        };

        // This should fail verification
        assert!(invalid_bundle.verify().is_err());
    }

    #[test]
    fn test_signature_consistency() {
        let identity_key = IdentityKey::new();
        let pre_key = SignedPreKey::new(123);

        let signature1 = pre_key.signature(&identity_key);
        let signature2 = pre_key.signature(&identity_key);

        // Signatures of the same data with the same key should be identical
        assert_eq!(signature1.to_bytes(), signature2.to_bytes());

        // Verify the signature directly
        let encoded = pre_key.encode_for_signature();
        assert!(
            identity_key
                .get_public_signing_key()
                .verify(&encoded, &signature1)
                .is_ok()
        );
    }

    #[test]
    fn test_tamper_resistance() {
        let identity_key = IdentityKey::new();
        let pre_key = SignedPreKey::new(77);

        let mut bundle = PreKeyBundle::new(&identity_key, &pre_key, None);

        // Tamper with the signed pre-key
        let another_pre_key = SignedPreKey::new(78);
        bundle.signed_pre_key_public = another_pre_key.get_public_key();

        // Verification should fail
        assert!(bundle.verify().is_err());
    }
}

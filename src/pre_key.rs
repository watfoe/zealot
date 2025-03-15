use crate::{IdentityKey, OneTimePreKey, X25519PublicKey, X25519Secret};
use ed25519_dalek::Verifier;
use rand::TryRngCore;
use rand::rngs::OsRng;

pub struct SignedPreKey {
    pre_key: X25519Secret,
    id: u32, // for referencing this pre-key
    created_at: std::time::SystemTime,
}

impl SignedPreKey {
    pub fn new(id: u32) -> Self {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();

        Self {
            pre_key: X25519Secret::from(seed),
            id,
            created_at: std::time::SystemTime::now(),
        }
    }

    pub fn public_key(&self) -> X25519PublicKey {
        self.pre_key.public_key()
    }

    pub fn key_pair(&self) -> X25519Secret {
        self.pre_key.clone()
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn dh(&self, public_key: &X25519PublicKey) -> [u8; 32] {
        self.pre_key.dh(public_key).to_bytes()
    }

    // Generate a signature for this pre-key using the identity key
    pub fn signature(&self, identity_key: &IdentityKey) -> ed25519_dalek::Signature {
        let encoded = self.encode_for_signature();
        identity_key.sign(&encoded)
    }

    fn encode_for_signature(&self) -> [u8; 32] {
        self.public_key().to_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 44] {
        let mut result = [0u8; 44];

        // Add the ID (4 bytes)
        result[0..4].copy_from_slice(&self.id.to_be_bytes());

        // Add the creation timestamp
        let timestamp = self
            .created_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        result[4..12].copy_from_slice(&timestamp.to_be_bytes());

        // Add the key bytes
        result[12..44].copy_from_slice(self.pre_key.as_bytes());

        result
    }
}

impl From<[u8; 44]> for SignedPreKey {
    /// Load a signed pre key from a byte array.
    fn from(bytes: [u8; 44]) -> Self {
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

        Self {
            pre_key: X25519Secret::from(key_bytes),
            id,
            created_at,
        }
    }
}

pub struct PreKeyBundle {
    public_identity_key_dh: X25519PublicKey,
    public_identity_key_verifier: ed25519_dalek::VerifyingKey,
    signed_pre_key_id: u32,
    public_signed_pre_key: X25519PublicKey,
    signature: ed25519_dalek::Signature,
    public_one_time_pre_key: Option<X25519PublicKey>,
}

impl PreKeyBundle {
    pub fn new(
        identity_key: &IdentityKey,
        signed_pre_key: &SignedPreKey,
        one_time_pre_key: Option<&OneTimePreKey>,
    ) -> Self {
        let public_identity_key_dh = identity_key.public_dh_key();
        let public_identity_key_verifier = identity_key.public_signing_key();
        let public_signed_pre_key = signed_pre_key.public_key();
        let signature = signed_pre_key.signature(identity_key);

        Self {
            public_identity_key_dh,
            public_identity_key_verifier,
            signed_pre_key_id: signed_pre_key.id(),
            public_signed_pre_key,
            signature,
            public_one_time_pre_key: one_time_pre_key.map(|key| key.public_key()),
        }
    }

    pub fn verify(&self) -> Result<(), ed25519_dalek::ed25519::Error> {
        let encoded_key = self.public_signed_pre_key.to_bytes();
        self.public_identity_key_verifier
            .verify(&encoded_key, &self.signature)
    }

    pub fn public_signed_pre_key(&self) -> X25519PublicKey {
        self.public_signed_pre_key
    }

    pub fn signed_pre_key_id(&self) -> u32 {
        self.signed_pre_key_id
    }

    pub fn public_identity_key(&self) -> X25519PublicKey {
        self.public_identity_key_dh
    }

    pub fn public_identity_key_verifier(&self) -> ed25519_dalek::VerifyingKey {
        self.public_identity_key_verifier
    }

    pub fn public_one_time_pre_key(&self) -> Option<X25519PublicKey> {
        self.public_one_time_pre_key
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
        assert_eq!(pre_key.id(), 123);

        // Ensure the key is properly initialized
        let public_key = pre_key.public_key();
        assert!(!public_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_pre_key_serialization() {
        let original_key = SignedPreKey::new(42);
        let serialized = original_key.to_bytes();

        // Ensure we have enough bytes (4 for ID, 8 for timestamp, 32 for key)
        assert_eq!(serialized.len(), 44);

        // Deserialize and check if it matches
        let deserialized_key = SignedPreKey::from(serialized);
        assert_eq!(deserialized_key.id(), original_key.id());
        assert_eq!(
            deserialized_key.public_key().as_bytes(),
            original_key.public_key().as_bytes()
        );
    }

    #[test]
    fn test_diffie_hellman() {
        let alice_key = SignedPreKey::new(1);
        let bob_key = SignedPreKey::new(2);

        let alice_public = alice_key.public_key();
        let bob_public = bob_key.public_key();

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
            public_identity_key_dh: identity_key.public_dh_key(),
            public_identity_key_verifier: another_identity.public_signing_key(), // Wrong verify key
            signed_pre_key_id: pre_key.id(),
            public_signed_pre_key: pre_key.public_key(),
            signature: pre_key.signature(&identity_key),
            public_one_time_pre_key: None,
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
                .public_signing_key()
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
        bundle.public_signed_pre_key = another_pre_key.public_key();

        // Verification should fail
        assert!(bundle.verify().is_err());
    }
}

use crate::{Error, IdentityKey, OneTimePreKey, X25519PublicKey, X25519Secret};
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::TryRngCore;
use rand::rngs::OsRng;

/// A medium-term signed pre-key as defined in Signal's X3DH protocol.
///
/// In X3DH, signed pre-keys (SPK) are medium-term keys that are signed with
/// the user's identity key to provide authentication. They are typically
/// rotated periodically (e.g., weekly or monthly).
pub struct SignedPreKey {
    pre_key: X25519Secret,
    id: u32, // for referencing this pre-key
    created_at: std::time::SystemTime,
}

impl SignedPreKey {
    /// Creates a new signed pre-key with the given ID.
    pub fn new(id: u32) -> Self {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();

        Self {
            pre_key: X25519Secret::from(seed),
            id,
            created_at: std::time::SystemTime::now(),
        }
    }

    /// Returns the public component of this signed pre-key.
    pub fn public_key(&self) -> X25519PublicKey {
        self.pre_key.public_key()
    }

    /// Returns the complete key pair for this signed pre-key.
    pub fn key_pair(&self) -> X25519Secret {
        self.pre_key.clone()
    }

    /// Returns the unique identifier for this signed pre-key.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Performs a Diffie-Hellman key agreement with the other party's public key.
    pub fn dh(&self, public_key: &X25519PublicKey) -> [u8; 32] {
        self.pre_key.dh(public_key).to_bytes()
    }

    /// Generates a signature for this pre-key using the provided identity key.
    ///
    /// The signature proves that the signed pre-key belongs to the
    /// owner of the identity key, providing authentication.
    pub fn signature(&self, identity_key: &IdentityKey) -> Signature {
        let encoded = self.encode_for_signature();
        identity_key.sign(&encoded)
    }

    fn encode_for_signature(&self) -> [u8; 32] {
        self.public_key().to_bytes()
    }

    /// Serializes the signed pre-key to a 44-byte array for storage.
    ///
    /// The format is:
    /// - 4 bytes: ID (big-endian u32)
    /// - 8 bytes: Creation timestamp (big-endian u64 seconds since UNIX epoch)
    /// - 32 bytes: X25519 key
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
    /// Deserializes a signed pre-key from a 44-byte array.
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

/// A bundle of public keys used for X3DH key agreement.
///
/// A PreKeyBundle contains all the public key material needed by another user
/// to establish a secure session asynchronously using the X3DH protocol:
/// - Identity key for authentication and key agreement
/// - Signed pre-key with signature for authenticated key agreement
/// - Optional one-time pre-key for additional security
pub struct PreKeyBundle {
    pub(crate) public_identity_key_dh: X25519PublicKey,
    pub(crate) public_identity_key_verifier: VerifyingKey,
    pub(crate) public_signed_pre_key: X25519PublicKey,
    pub(crate) signature: Signature,
    pub(crate) signed_pre_key_id: u32,
    pub(crate) public_one_time_pre_key: Option<X25519PublicKey>,
}

impl PreKeyBundle {
    /// Creates a new pre-key bundle from the provided keys.
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

    /// Verifies the bundle's signature to ensure authenticity.
    ///
    /// This verification confirms that the signed pre-key
    /// was actually created by the owner of the identity key.
    ///
    /// # Returns
    ///
    /// Ok(()) if the signature is valid, or an Err otherwise.
    pub fn verify(&self) -> Result<(), Error> {
        let encoded_key = self.public_signed_pre_key.to_bytes();
        self.public_identity_key_verifier
            .verify(&encoded_key, &self.signature)
            .map_err(|err| Error::PreKey(err.to_string()))
    }

    /// Returns the public signed pre-key (SPK_pub) from this bundle.
    pub fn public_signed_pre_key(&self) -> X25519PublicKey {
        self.public_signed_pre_key
    }

    /// Returns the ID of the signed pre-key in this bundle.
    pub fn signed_pre_key_id(&self) -> u32 {
        self.signed_pre_key_id
    }

    /// Returns the public identity key (IK_pub) for DH operations.
    pub fn public_identity_key(&self) -> X25519PublicKey {
        self.public_identity_key_dh
    }

    /// Returns the public verification key for the identity.
    pub fn public_identity_key_verifier(&self) -> VerifyingKey {
        self.public_identity_key_verifier
    }

    /// Returns the optional one-time pre-key (OPK_pub) from this bundle.
    pub fn public_one_time_pre_key(&self) -> Option<X25519PublicKey> {
        self.public_one_time_pre_key
    }

    /// Returns the optional one-time pre-key (OPK_pub) from this bundle.
    pub fn signature(&self) -> Signature {
        self.signature
    }

    pub fn try_from(
        public_identity_key_dh: [u8; 32],
        public_identity_key_verifier: [u8; 32],
        public_signed_pre_key: [u8; 32],
        signature: [u8; 64],
        signed_pre_key_id: u32,
        public_one_time_pre_key: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        Ok(Self {
            public_identity_key_dh: X25519PublicKey::from(public_identity_key_dh),
            public_identity_key_verifier: VerifyingKey::from_bytes(&public_identity_key_verifier)
                .map_err(|err| Error::Serde(err.to_string()))?,
            public_signed_pre_key: X25519PublicKey::from(public_signed_pre_key),
            signature: Signature::from_bytes(&SignatureBytes::from(signature)),
            signed_pre_key_id,
            public_one_time_pre_key: public_one_time_pre_key
                .map(|otpk| X25519PublicKey::from(otpk)),
        })
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

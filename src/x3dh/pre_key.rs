use crate::{Error, IdentityKey, generate_random_seed};
use crate::{X25519PublicKey, X25519Secret};
use ed25519_dalek::Signature;
use std::collections::HashMap;
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A medium-term signed pre-key as defined in Signal's X3DH protocol.
///
/// Signed pre-keys are medium-term keys that are signed with the user's
/// identity key to provide authentication. They are typically rotated
/// periodically (e.g., weekly or monthly).
pub struct SignedPreKey {
    pre_key: X25519Secret,
    id: u32,
}

impl SignedPreKey {
    /// Creates a new signed pre-key with the given ID.
    pub fn new(id: u32) -> Result<Self, Error> {
        let seed = generate_random_seed().map_err(|_| Error::Random)?;

        Ok(Self {
            pre_key: X25519Secret::from(seed),
            id,
        })
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

    /// Performs Diffie-Hellman key agreement with the other party's public key.
    pub fn dh(&self, public_key: &X25519PublicKey) -> SharedSecret {
        self.pre_key.dh(public_key)
    }

    /// Generates a signature for this pre-key using the provided identity key.
    ///
    /// The signature proves that the signed pre-key belongs to the owner of
    /// the identity key, providing authentication.
    pub fn signature(&self, identity_key: &IdentityKey) -> Signature {
        let encoded = self.public_key().to_bytes();
        identity_key.sign(&encoded)
    }

    /// Serializes the signed pre-key to a 36-byte array.
    ///
    /// The format is:
    /// - 4 bytes: ID (big-endian u32)
    /// - 32 bytes: X25519 private key
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut result = [0u8; 36];

        result[0..4].copy_from_slice(&self.id.to_be_bytes());
        result[4..].copy_from_slice(self.pre_key.as_bytes());

        result
    }
}

impl From<[u8; 36]> for SignedPreKey {
    /// Deserializes a signed pre-key from a 36-byte array.
    fn from(bytes: [u8; 36]) -> Self {
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&bytes[0..4]);
        let id = u32::from_be_bytes(id_bytes);

        let mut key_bytes = Box::new([0u8; 32]);
        key_bytes.copy_from_slice(&bytes[4..]);

        Self {
            pre_key: X25519Secret::from(key_bytes),
            id,
        }
    }
}

impl Zeroize for SignedPreKey {
    fn zeroize(&mut self) {
        self.pre_key.zeroize();
        self.id = 0;
    }
}

impl ZeroizeOnDrop for SignedPreKey {}

/// Storage for signed pre-keys with automatic rotation and ID management.
pub struct SignedPreKeyStore {
    pub(crate) keys: HashMap<u32, SignedPreKey>,
    pub(crate) next_id: u32,
    pub(crate) max_keys: usize,
}

impl SignedPreKeyStore {
    pub(crate) fn new(max_keys: usize) -> Result<Self, Error> {
        let mut keys = HashMap::with_capacity(max_keys);
        let id = 1;
        keys.insert(id, SignedPreKey::new(id)?);

        Ok(Self {
            keys,
            next_id: id + 1,
            max_keys,
        })
    }

    pub(crate) fn renew_key(&mut self) -> Result<(u32, &SignedPreKey), Error> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.keys.insert(id, SignedPreKey::new(id)?);

        Ok((id, self.get_current()))
    }

    pub(crate) fn get(&self, id: u32) -> Option<&SignedPreKey> {
        self.keys.get(&id)
    }

    /// Returns the most recently created signed pre-key.
    pub(crate) fn get_current(&self) -> &SignedPreKey {
        let current_id = self.next_id - 1;
        self.keys.get(&current_id).unwrap()
    }
}

impl Zeroize for SignedPreKeyStore {
    fn zeroize(&mut self) {
        for (_, key) in self.keys.iter_mut() {
            key.zeroize();
        }
        self.keys.clear();
        self.next_id = 0;
        self.max_keys = 0;
    }
}

impl ZeroizeOnDrop for SignedPreKeyStore {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKey;

    #[test]
    fn test_signed_pre_key_creation() {
        let pre_key = SignedPreKey::new(13).unwrap();

        // Check the ID is set correctly
        assert_eq!(pre_key.id(), 13);

        // Ensure the key is properly initialized
        let public_key = pre_key.public_key();
        assert!(!public_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_pre_key_serialization() {
        let original_key = SignedPreKey::new(21).unwrap();
        let serialized = original_key.to_bytes();

        // Ensure we have enough bytes (4 for ID, 32 for key)
        assert_eq!(serialized.len(), 36);

        // Deserialize and check if it matches
        let deserialized_key = SignedPreKey::from(serialized);
        assert_eq!(deserialized_key.id(), original_key.id());
        assert_eq!(
            deserialized_key.public_key().as_bytes(),
            original_key.public_key().as_bytes()
        );
    }

    #[test]
    fn test_signature_consistency() {
        let identity_key = IdentityKey::new().unwrap();
        let pre_key = SignedPreKey::new(13).unwrap();

        let signature1 = pre_key.signature(&identity_key);
        let signature2 = pre_key.signature(&identity_key);

        // Signatures of the same data with the same key should be identical
        assert_eq!(signature1.to_bytes(), signature2.to_bytes());

        // Verify the signature directly
        let encoded = pre_key.public_key().to_bytes();
        assert!(
            identity_key
                .signing_key_public()
                .verify_strict(&encoded, &signature1)
                .is_ok()
        );
    }
}

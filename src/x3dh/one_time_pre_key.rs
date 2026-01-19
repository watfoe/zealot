use crate::{Error, X25519PublicKey, X25519Secret, generate_random_seed};
use std::collections::HashMap;
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A one-time pre-key as defined in Signal's X3DH protocol.
///
/// One-time pre-keys provide additional security by ensuring forward secrecy
/// even if the signed pre-key is compromised. Each key should be used at most
/// once and then discarded.
#[derive(Clone)]
pub struct OneTimePreKey {
    pre_key: X25519Secret,
    id: u32,
    used: bool,
}

impl OneTimePreKey {
    /// Creates a new one-time pre-key with the given ID.
    pub fn new(id: u32) -> Self {
        Self {
            pre_key: X25519Secret::from(generate_random_seed()),
            id,
            used: false,
        }
    }

    /// Returns the public component of this pre-key.
    pub fn public_key(&self) -> X25519PublicKey {
        self.pre_key.public_key()
    }

    /// Returns the unique identifier for this pre-key.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Checks if this pre-key has been used.
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Marks this pre-key as used, preventing future use.
    pub fn mark_as_used(&mut self) {
        self.used = true;
    }

    /// Performs Diffie-Hellman key agreement with the provided public key.
    ///
    /// This consumes the pre-key to prevent reuse. Returns an error if the
    /// pre-key has already been used.
    pub fn dh(self, public_key: &X25519PublicKey) -> Result<SharedSecret, Error> {
        if self.used {
            return Err(Error::PreKey("Pre-key already used".to_string()));
        }

        Ok(self.pre_key.dh(public_key))
    }

    /// Serializes the one-time pre-key to a 37-byte array.
    ///
    /// The format is:
    /// - 4 bytes: ID (big-endian u32)
    /// - 1 byte: Used flag (0 = unused, 1 = used)
    /// - 32 bytes: X25519 private key
    pub fn to_bytes(&self) -> [u8; 37] {
        let mut result = [0u8; 37];

        result[0..4].copy_from_slice(&self.id.to_be_bytes());
        result[4] = if self.used { 1 } else { 0 };
        result[5..].copy_from_slice(self.pre_key.as_bytes());

        result
    }
}

impl From<[u8; 37]> for OneTimePreKey {
    /// Deserializes a one-time pre-key from a 37-byte array.
    fn from(bytes: [u8; 37]) -> Self {
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&bytes[0..4]);
        let id = u32::from_be_bytes(id_bytes);
        let used = bytes[4] != 0;

        let mut key_bytes = Box::new([0u8; 32]);
        key_bytes.copy_from_slice(&bytes[5..]);

        Self {
            pre_key: X25519Secret::from(key_bytes),
            id,
            used,
        }
    }
}

impl Zeroize for OneTimePreKey {
    fn zeroize(&mut self) {
        self.pre_key.zeroize();
        self.id = 0;
        self.used = false;
    }
}

impl ZeroizeOnDrop for OneTimePreKey {}

/// Storage for one-time pre-keys with automatic ID management.
pub(crate) struct OneTimePreKeyStore {
    pub(crate) keys: HashMap<u32, OneTimePreKey>,
    pub(crate) next_id: u32,
    pub(crate) max_keys: usize,
}

impl OneTimePreKeyStore {
    /// Creates a new one-time pre-key store with the specified maximum key count.
    pub(crate) fn new(max_keys: usize) -> Self {
        Self {
            keys: HashMap::with_capacity(max_keys),
            next_id: 1,
            max_keys,
        }
    }

    /// Generates a specified number of new one-time pre-keys.
    pub(crate) fn generate_keys(
        &mut self,
        count: usize,
    ) -> HashMap<u32, X25519PublicKey> {
        let mut keys = HashMap::with_capacity(count);
        for _ in 0..count {
            let id = self.next_id;
            let key = OneTimePreKey::new(id);
            let key_public = key.public_key();
            self.next_id = self.next_id.wrapping_add(1);
            self.keys.insert(id, key);
            keys.insert(id, key_public);
        }

        keys
    }

    /// Returns a map of all available pre-key IDs to their public keys.
    pub(crate) fn public_keys(&self) -> HashMap<u32, X25519PublicKey> {
        let mut indexed_pks = HashMap::with_capacity(self.keys.len());
        self.keys.iter().for_each(|(idx, otpk)| {
            indexed_pks.insert(*idx, otpk.public_key());
        });

        indexed_pks
    }

    /// Removes and returns a one-time pre-key by its ID.
    pub(crate) fn take(&mut self, id: u32) -> Option<OneTimePreKey> {
        self.keys.remove(&id)
    }

    /// Returns the current number of pre-keys in the store.
    pub(crate) fn count(&self) -> usize {
        self.keys.len()
    }

    /// Generates additional pre-keys to maintain the desired pool size.
    pub(crate) fn replenish(&mut self) -> HashMap<u32, X25519PublicKey> {
        let needed = self.max_keys.saturating_sub(self.keys.len());
        self.generate_keys(needed)
    }
}

impl Zeroize for OneTimePreKeyStore {
    fn zeroize(&mut self) {
        for (_, key) in self.keys.iter_mut() {
            key.zeroize();
        }
        self.keys.clear();
        self.next_id = 0;
        self.max_keys = 0;
    }
}

impl ZeroizeOnDrop for OneTimePreKeyStore {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_time_pre_key_creation() {
        let pre_key = OneTimePreKey::new(13);

        assert_eq!(pre_key.id(), 13);
        assert!(!pre_key.is_used());

        // Check that the public key is properly initialized
        let public_key = pre_key.public_key();
        assert!(!public_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_one_time_pre_key_marking_as_used() {
        let mut pre_key = OneTimePreKey::new(1);
        assert!(!pre_key.is_used());

        pre_key.mark_as_used();
        assert!(pre_key.is_used());
    }

    #[test]
    fn test_one_time_pre_key_serialization() {
        let original_key = OneTimePreKey::new(123);
        let serialized = original_key.to_bytes();

        // Ensure we have enough bytes (4 for ID, 1 for used, 32 for key)
        assert_eq!(serialized.len(), 37);

        // Deserialize and check if it matches
        let deserialized_key = OneTimePreKey::from(serialized);
        assert_eq!(deserialized_key.id(), original_key.id());
        assert_eq!(deserialized_key.is_used(), original_key.is_used());
        assert_eq!(
            deserialized_key.public_key().as_bytes(),
            original_key.public_key().as_bytes()
        );
    }

    #[test]
    fn test_one_time_pre_key_cannot_be_reused() {
        let mut key = OneTimePreKey::new(1);
        let other_public = OneTimePreKey::new(2).public_key();

        // Mark key as used
        key.mark_as_used();

        // Attempt to use it for DH should fail
        assert!(key.dh(&other_public).is_err());
    }
}

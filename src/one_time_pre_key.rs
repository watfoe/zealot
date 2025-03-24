use crate::{Error, X25519PublicKey, X25519Secret};
use rand::TryRngCore;
use rand::rngs::OsRng;
use std::collections::HashMap;

/// A one-time pre-key as defined in Signal's X3DH protocol.
///
/// One-time pre-keys (OPK) provide additional security by ensuring
/// forward secrecy even if the signed pre-key is compromised. Each key should
/// be used at most once and then discarded.
#[derive(Clone)]
pub struct OneTimePreKey {
    pre_key: X25519Secret,
    id: u32,
    used: bool,
}

impl OneTimePreKey {
    /// Creates a new one-time pre-key with the given ID.
    pub fn new(id: u32) -> Self {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();

        Self {
            pre_key: X25519Secret::from(seed),
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

    /// Performs a Diffie-Hellman key agreement with the provided public key.
    pub fn dh(self, public_key: &X25519PublicKey) -> Result<[u8; 32], Error> {
        if self.used {
            return Err(Error::PreKey("Pre-key already used".to_string()));
        }

        Ok(self.pre_key.dh(public_key).to_bytes())
    }

    /// Serializes the one-time pre-key to a 37-byte array for storage.
    ///
    /// The format is:
    /// - 4 bytes: ID (big-endian u32)
    /// - 1 byte: Used flag (0 = unused, 1 = used)
    /// - 32 bytes: X25519 key
    pub fn to_bytes(&self) -> [u8; 37] {
        let mut result = [0u8; 37];

        // Add the ID (4 bytes)
        result[0..4].copy_from_slice(&self.id.to_be_bytes());

        // Add the used flag (1 byte)
        result[4] = if self.used { 1 } else { 0 };

        // Add the key bytes (32 bytes)
        result[5..].copy_from_slice(self.pre_key.as_bytes());

        result
    }
}

impl From<[u8; 37]> for OneTimePreKey {
    /// Deserializes a one-time pre-key from a 45-byte array.
    fn from(bytes: [u8; 37]) -> Self {
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&bytes[0..4]);
        let id = u32::from_be_bytes(id_bytes);

        // Extract the used flag
        let used = bytes[4] != 0;

        // Extract the key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes[5..]);

        Self {
            pre_key: X25519Secret::from(key_bytes),
            id,
            used,
        }
    }
}

pub struct OneTimePreKeyStore {
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
    pub(crate) fn generate_keys(&mut self, count: usize) -> Vec<u32> {
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let id = self.next_id;
            self.next_id += 1;
            self.keys.insert(id, OneTimePreKey::new(id));
            ids.push(id);
        }
        ids
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
    pub(crate) fn replenish(&mut self) -> Vec<u32> {
        let needed = self.max_keys.saturating_sub(self.keys.len());
        self.generate_keys(needed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_time_pre_key_creation() {
        let pre_key = OneTimePreKey::new(42);

        assert_eq!(pre_key.id(), 42);
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
    fn test_one_time_pre_key_diffie_hellman() {
        let alice_key = OneTimePreKey::new(1);
        let bob_key = OneTimePreKey::new(2);

        // Get public keys
        let alice_public = alice_key.public_key();
        let bob_public = bob_key.public_key();

        // Perform DH exchange - note that these consume the keys
        let shared_alice = alice_key.dh(&bob_public).unwrap();
        let shared_bob = bob_key.dh(&alice_public).unwrap();

        // Both should compute the same shared secret
        assert_eq!(shared_alice, shared_bob);
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

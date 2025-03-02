use rand_core::{OsRng, TryRngCore};
use x25519_dalek::StaticSecret;

#[derive(Clone)]
pub struct OneTimePreKey {
    pre_key: StaticSecret,
    id: u32,
    created_at: std::time::SystemTime,
    used: bool,
}

impl OneTimePreKey {
    pub fn new(id: u32) -> Self {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();
        let pre_key = StaticSecret::from(seed);

        Self {
            pre_key,
            id,
            created_at: std::time::SystemTime::now(),
            used: false,
        }
    }

    pub fn get_public_key(&self) -> x25519_dalek::PublicKey {
        (&self.pre_key).into()
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    pub fn is_used(&self) -> bool {
        self.used
    }

    pub fn mark_as_used(&mut self) {
        self.used = true;
    }

    pub fn dh(self, public_key: &x25519_dalek::PublicKey) -> Result<[u8; 32], &'static str> {
        if self.used {
            return Err("Pre-key already used");
        }

        Ok(self.pre_key.diffie_hellman(public_key).to_bytes())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Add the ID (4 bytes)
        result.extend_from_slice(&self.id.to_be_bytes());

        // Add the creation timestamp (8 bytes)
        let timestamp = self
            .created_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        result.extend_from_slice(&timestamp.to_be_bytes());

        // Add the used flag (1 byte)
        result.push(if self.used { 1 } else { 0 });

        // Add the key bytes (32 bytes)
        result.extend_from_slice(self.pre_key.as_bytes());

        result
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 + 8 + 1 + 32 {
            // 4 bytes ID + 8 bytes timestamp + 1 byte used flag + 32 bytes key
            return Err("Invalid one-time pre-key data length");
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

        // Extract the used flag
        let used = bytes[12] != 0;

        // Extract the key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes[13..45]);
        let pre_key = StaticSecret::from(key_bytes);

        Ok(Self {
            pre_key,
            id,
            created_at,
            used,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_time_pre_key_creation() {
        let pre_key = OneTimePreKey::new(42);

        assert_eq!(pre_key.get_id(), 42);
        assert!(!pre_key.is_used());

        // Check that the public key is properly initialized
        let public_key = pre_key.get_public_key();
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
        let serialized = original_key.serialize();

        // Ensure we have the right size
        assert_eq!(serialized.len(), 4 + 8 + 1 + 32);

        // Deserialize and check if it matches
        let deserialized_key = OneTimePreKey::deserialize(&serialized).unwrap();
        assert_eq!(deserialized_key.get_id(), original_key.get_id());
        assert_eq!(deserialized_key.is_used(), original_key.is_used());
        assert_eq!(
            deserialized_key.get_public_key().as_bytes(),
            original_key.get_public_key().as_bytes()
        );

        // Test with invalid data
        let invalid_data = vec![0; 20]; // Too short
        assert!(OneTimePreKey::deserialize(&invalid_data).is_err());
    }

    #[test]
    fn test_one_time_pre_key_diffie_hellman() {
        let alice_key = OneTimePreKey::new(1);
        let bob_key = OneTimePreKey::new(2);

        // Get public keys
        let alice_public = alice_key.get_public_key();
        let bob_public = bob_key.get_public_key();

        // Perform DH exchange - note that these consume the keys
        let shared_alice = alice_key.dh(&bob_public).unwrap();
        let shared_bob = bob_key.dh(&alice_public).unwrap();

        // Both should compute the same shared secret
        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_one_time_pre_key_cannot_be_reused() {
        let mut key = OneTimePreKey::new(1);
        let other_public = OneTimePreKey::new(2).get_public_key();

        // Mark key as used
        key.mark_as_used();

        // Attempt to use it for DH should fail
        assert!(key.dh(&other_public).is_err());
    }
}

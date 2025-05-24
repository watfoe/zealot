use crate::{Error, X25519PublicKey, X25519Secret};
use ed25519_dalek::Signer;
use ed25519_dalek::{SecretKey, SigningKey, Verifier, ed25519};
use rand::TryRngCore;
use rand::rngs::OsRng;

/// Generates a cryptographically secure random 32-byte seed.
pub fn generate_random_seed() -> Result<[u8; 32], Error> {
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).map_err(|_| Error::Random)?;
    Ok(seed)
}

fn generate_ed25519_signing_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&SecretKey::from(seed))
}

/// Long-term identity key pair that combines signing and key agreement capabilities.
///
/// An `IdentityKey` contains both an Ed25519 signing key for authentication and
/// an X25519 key for Diffie-Hellman key agreement, derived from the same seed
/// for security and convenience.
pub struct IdentityKey {
    signing_key: SigningKey,
    dh_key: X25519Secret,
}

impl Default for IdentityKey {
    /// Creates a new identity key with randomly generated components.
    fn default() -> Self {
        let seed = generate_random_seed().unwrap();
        let signing_key = generate_ed25519_signing_key(seed);

        Self {
            signing_key,
            dh_key: X25519Secret::from(seed),
        }
    }
}

impl IdentityKey {
    /// Creates a new identity key with randomly generated components.
    pub fn new() -> Self {
        Self::default()
    }

    /// Signs a message using the Ed25519 signing key.
    ///
    /// # Returns
    ///
    /// An Ed25519 signature that can be verified with this identity's public key.
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.signing_key.sign(message)
    }

    /// Verifies a signature using this identity's public key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), ed25519::Error> {
        let verifying_key = self.signing_key.verifying_key();
        verifying_key.verify(message, signature)
    }

    /// Returns the public Ed25519 signing key corresponding to this identity.
    pub fn signing_key_public(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the public X25519 key for Diffie-Hellman operations.
    pub fn dh_key_public(&self) -> X25519PublicKey {
        self.dh_key.public_key()
    }

    /// Performs a Diffie-Hellman key agreement with another party's public key.
    ///
    /// # Returns
    ///
    /// A 32-byte array shared secret that both parties can derive.
    pub fn dh(&self, public_key: &X25519PublicKey) -> [u8; 32] {
        self.dh_key.dh(public_key).to_bytes()
    }

    /// Serializes the identity key to a 64-byte array.
    ///
    /// The first 32 bytes contain the Ed25519 private key,
    /// and the last 32 bytes contain the X25519 public key.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(self.signing_key.as_bytes().as_slice());
        bytes[32..64].copy_from_slice(self.dh_key.as_bytes());

        bytes
    }
}

impl From<[u8; 64]> for IdentityKey {
    /// Deserializes an identity key from a 64-byte array.
    fn from(bytes: [u8; 64]) -> Self {
        let mut private_sk_bytes = [0u8; 32];
        private_sk_bytes.copy_from_slice(&bytes[0..32]);
        let signing_key_private = SecretKey::from(private_sk_bytes);
        let signing_key = SigningKey::from_bytes(&signing_key_private);

        let mut private_dh_bytes = [0u8; 32];
        private_dh_bytes.copy_from_slice(&bytes[32..64]);
        let dh_key = X25519Secret::from(private_dh_bytes);

        Self {
            signing_key,
            dh_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_identity_key_creation() {
        let identity_key = IdentityKey::new();

        // Ensure keys are properly initialized
        assert!(!identity_key.signing_key.as_bytes().iter().all(|&b| b == 0));
        assert!(!identity_key.dh_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_signing_and_verification() {
        let identity_key = IdentityKey::new();
        let message = b"This is a test message";

        // Sign the message
        let signature = identity_key.sign(message);

        // Verify the signature
        assert!(identity_key.verify(message, &signature).is_ok());

        // Modify the message and ensure verification fails
        let modified_message = b"This is a modified message";
        assert!(identity_key.verify(modified_message, &signature).is_err());
    }

    #[test]
    fn test_diffie_hellman() {
        // Create two identity keys
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();

        // Get Bob's public DH key
        let bob_public = bob_identity.dh_key_public();

        // Alice computes the shared secret
        let alice_shared = alice_identity.dh(&bob_public);

        // Get Alice's public DH key
        let alice_public = alice_identity.dh_key_public();

        // Bob computes the shared secret
        let bob_shared = bob_identity.dh(&alice_public);

        // Ensure both computed the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_serialization_deserialization() {
        let original_key = IdentityKey::new();
        let serialized = original_key.to_bytes();

        // Ensure serialized data has the expected length
        assert_eq!(serialized.len(), 64);

        // Deserialize back to an identity key
        let deserialized_key = IdentityKey::from(serialized);

        // Ensure the keys match after round-trip serialization
        assert_eq!(
            original_key.signing_key.as_bytes(),
            deserialized_key.signing_key.as_bytes()
        );
        assert_eq!(
            original_key.dh_key.as_bytes(),
            deserialized_key.dh_key.as_bytes()
        );
    }

    #[test]
    fn test_common_seed_derivation() {
        // Generate a random seed
        let seed = generate_random_seed().unwrap();

        // Create signing and DH keys from the same seed
        let signing_key = generate_ed25519_signing_key(seed);

        // Create a new identity key directly
        let identity_key = IdentityKey {
            signing_key,
            dh_key: X25519Secret::from(seed),
        };

        // Test signing with the derived key
        let message = b"Test message";
        let signature = identity_key.sign(message);

        // Verify the signature
        assert!(
            identity_key
                .signing_key
                .verifying_key()
                .verify(message, &signature)
                .is_ok()
        );
    }
}

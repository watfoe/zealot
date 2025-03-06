use crate::Error;
use ed25519_dalek::Signer;
use ed25519_dalek::{SecretKey, SigningKey, Verifier, ed25519};
use rand::TryRngCore;
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

pub fn generate_random_seed() -> Result<[u8; 32], Error> {
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).map_err(|_| Error::Random)?;
    Ok(seed)
}

fn generate_ed25519_signing_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&SecretKey::from(seed))
}

fn generate_x25519_dh_key(seed: [u8; 32]) -> StaticSecret {
    StaticSecret::from(seed)
}

pub struct IdentityKey {
    signing_key: SigningKey,
    dh_key: StaticSecret,
}

impl IdentityKey {
    pub fn new() -> Self {
        let seed = generate_random_seed().unwrap();

        let signing_key = generate_ed25519_signing_key(seed);
        let dh_key = generate_x25519_dh_key(seed);

        Self {
            signing_key,
            dh_key,
        }
    }

    // Method to sign data using the identity key
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), ed25519::Error> {
        let verifying_key = self.signing_key.verifying_key();
        verifying_key.verify(message, &signature)
    }

    // Get the public Ed25519 verifying key
    pub fn get_public_signing_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    // Get the public X25519 key for DH operations
    pub fn get_public_dh_key(&self) -> x25519_dalek::PublicKey {
        (&self.dh_key).into()
    }

    pub fn dh(&self, public_key: &x25519_dalek::PublicKey) -> [u8; 32] {
        self.dh_key.diffie_hellman(public_key).to_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(self.signing_key.as_bytes().as_slice());
        bytes[32..64].copy_from_slice(self.dh_key.as_bytes());

        bytes
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut private_sk_bytes = [0u8; 32];
        private_sk_bytes.copy_from_slice(&bytes[0..32]);
        let signing_key_private = SecretKey::from(private_sk_bytes);
        let signing_key = SigningKey::from_bytes(&signing_key_private);

        let mut private_dh_bytes = [0u8; 32];
        private_dh_bytes.copy_from_slice(&bytes[32..64]);
        let dh_key = StaticSecret::from(private_dh_bytes);

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
        let bob_public = bob_identity.get_public_dh_key();

        // Alice computes the shared secret
        let alice_shared = alice_identity.dh(&bob_public);

        // Get Alice's public DH key
        let alice_public = alice_identity.get_public_dh_key();

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
        let deserialized_key = IdentityKey::from_bytes(&serialized);

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
        let dh_key = generate_x25519_dh_key(seed);

        // Create a new identity key directly
        let identity_key = IdentityKey {
            signing_key,
            dh_key,
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

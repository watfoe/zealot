use crate::Error;
use crate::{X25519PublicKey, X25519Secret};
use ed25519_dalek::Signer;
use ed25519_dalek::{SecretKey, SigningKey, ed25519};
use rand::TryRngCore;
use rand::rngs::OsRng;
use x25519_dalek::SharedSecret;
use zeroize::Zeroize;

/// Generates a cryptographically secure random 32-byte seed.
pub(crate) fn generate_random_seed() -> Result<Box<[u8; 32]>, Error> {
    let mut seed = Box::new([0u8; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut_slice())
        .map_err(|_| Error::Random)?;
    Ok(seed)
}

/// Long-term identity key pair that combines signing and key agreement capabilities.
///
/// An `IdentityKey` contains both an Ed25519 signing key for authentication and
/// an X25519 key for Diffie-Hellman key agreement, derived from the same seed
/// for security and convenience.
pub struct IdentityKey {
    signing_key: Box<SigningKey>,
    dh_key: X25519Secret,
}

impl IdentityKey {
    /// Creates a new identity key with randomly generated components.
    pub fn new() -> Result<Self, Error> {
        let seed = generate_random_seed().map_err(|_| Error::Random)?;
        let signing_key = Box::new(SigningKey::from(SecretKey::from(*seed)));
        let dh_key = X25519Secret::from(seed);

        Ok(Self {
            signing_key,
            dh_key,
        })
    }

    /// Signs a message using the Ed25519 signing key.
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
        verifying_key.verify_strict(message, signature)
    }

    /// Returns the public Ed25519 signing key for this identity.
    pub fn signing_key_public(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the public X25519 key for Diffie-Hellman operations.
    pub fn dh_key_public(&self) -> X25519PublicKey {
        self.dh_key.public_key()
    }

    /// Performs Diffie-Hellman key agreement with another party's public key.
    pub fn dh(&self, public_key: &X25519PublicKey) -> SharedSecret {
        self.dh_key.dh(public_key)
    }

    /// Serializes the identity key to a 64-byte array.
    ///
    /// The first 32 bytes contain the Ed25519 private key,
    /// and the last 32 bytes contain the X25519 private key.
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
        let mut private_sk_bytes = Box::new([0u8; 32]);
        private_sk_bytes.copy_from_slice(&bytes[0..32]);
        let signing_key_private = SecretKey::from(*private_sk_bytes);
        let signing_key = Box::new(SigningKey::from_bytes(&signing_key_private));

        private_sk_bytes.zeroize();

        let mut private_dh_bytes = Box::new([0u8; 32]);
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

    #[test]
    fn test_signing_and_verification() {
        let identity_key = IdentityKey::new().unwrap();
        let message = b"This is a test message";

        let signature = identity_key.sign(message);
        assert!(identity_key.verify(message, &signature).is_ok());

        let modified_message = b"This is a modified message";
        assert!(identity_key.verify(modified_message, &signature).is_err());
    }

    #[test]
    fn test_serialization_deserialization() {
        let original_key = IdentityKey::new().unwrap();
        let serialized = original_key.to_bytes();

        // Ensure serialized data has the expected length
        assert_eq!(serialized.len(), 64);

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
}
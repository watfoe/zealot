use crate::{Error, IdentityKey, OneTimePreKey, X25519PublicKey, X25519Secret};
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::TryRngCore;
use rand::rngs::OsRng;
use std::collections::HashMap;

/// A medium-term signed pre-key as defined in Signal's X3DH protocol.
///
/// In X3DH, signed pre-keys (SPK) are medium-term keys that are signed with
/// the user's identity key to provide authentication. They are typically
/// rotated periodically (e.g., weekly or monthly).
pub struct SignedPreKey {
    pre_key: X25519Secret,
    id: u32, // for referencing this pre-key
}

impl SignedPreKey {
    /// Creates a new signed pre-key with the given ID.
    pub fn new(id: u32) -> Self {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();

        Self {
            pre_key: X25519Secret::from(seed),
            id,
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
        let encoded = self.public_key().to_bytes();
        identity_key.sign(&encoded)
    }

    /// Serializes the signed pre-key to a 44-byte array for storage.
    ///
    /// The format is:
    /// - 4 bytes: ID (big-endian u32)
    /// - 8 bytes: Creation timestamp (big-endian u64 seconds since UNIX epoch)
    /// - 32 bytes: X25519 key
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut result = [0u8; 36];

        // Add the ID (4 bytes)
        result[0..4].copy_from_slice(&self.id.to_be_bytes());

        // Add the key bytes
        result[4..].copy_from_slice(self.pre_key.as_bytes());

        result
    }
}

impl From<[u8; 36]> for SignedPreKey {
    /// Deserializes a signed pre-key from a 44-byte array.
    fn from(bytes: [u8; 36]) -> Self {
        // Extract the ID
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&bytes[0..4]);
        let id = u32::from_be_bytes(id_bytes);

        // Extract the key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes[4..]);

        Self {
            pre_key: X25519Secret::from(key_bytes),
            id,
        }
    }
}

pub struct SignedPreKeyStore {
    pub(crate) keys: HashMap<u32, SignedPreKey>,
    pub(crate) next_id: u32,
    pub(crate) max_keys: usize,
}

impl SignedPreKeyStore {
    pub(crate) fn new(max_keys: usize) -> Self {
        let mut keys = HashMap::with_capacity(max_keys);
        let id = 1;
        keys.insert(id, SignedPreKey::new(id));

        Self {
            keys,
            next_id: id + 1,
            max_keys,
        }
    }

    pub(crate) fn renew_key(&mut self) -> &SignedPreKey {
        let id = self.next_id;
        self.next_id += 1;
        self.keys.insert(id, SignedPreKey::new(id));

        self.get_current()
    }

    pub(crate) fn get(&self, id: u32) -> Option<&SignedPreKey> {
        self.keys.get(&id)
    }

    pub(crate) fn get_current(&self) -> &SignedPreKey {
        let current_id = self.next_id - 1;
        self.keys.get(&current_id).unwrap()
    }
}

/// A bundle of public keys used for X3DH key agreement.
///
/// A PreKeyBundle contains all the public key material needed by another user
/// to establish a secure session asynchronously using the X3DH protocol:
/// - Identity key for authentication and key agreement
/// - Signed pre-key with signature for authenticated key agreement
/// - Optional one-time pre-key for additional security
pub struct SessionPreKeyBundle {
    pub(crate) ik_public: X25519PublicKey,
    pub(crate) signing_key_public: VerifyingKey,
    pub(crate) spk_public: (u32, X25519PublicKey),
    pub(crate) signature: Signature,
    pub(crate) otpk_public: Option<(u32, X25519PublicKey)>,
}

impl SessionPreKeyBundle {
    /// Creates a new pre-key bundle from the provided keys.
    pub fn new(ik: &IdentityKey, spk: &SignedPreKey, otpk: Option<&OneTimePreKey>) -> Self {
        let ik_public = ik.dh_key_public();
        let signing_key_public = ik.signing_key_public();
        let spk_public = spk.public_key();
        let signature = spk.signature(ik);

        Self {
            ik_public,
            signing_key_public,
            spk_public: (spk.id(), spk_public),
            signature,
            otpk_public: otpk.map(|key| (key.id(), key.public_key())),
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
        let encoded_key = self.spk_public.1.to_bytes();
        self.signing_key_public
            .verify(&encoded_key, &self.signature)
            .map_err(|err| Error::PreKey(err.to_string()))
    }

    /// Returns the public signed pre-key (SPK_pub) from this bundle.
    pub fn spk_public(&self) -> (u32, X25519PublicKey) {
        self.spk_public
    }

    /// Returns the public identity key (IK_pub) for DH operations.
    pub fn ik_public(&self) -> X25519PublicKey {
        self.ik_public
    }

    /// Returns the public verification key for the identity.
    pub fn signing_key_public(&self) -> VerifyingKey {
        self.signing_key_public
    }

    /// Returns the optional one-time pre-key (OPK_pub) from this bundle.
    pub fn otpk_public(&self) -> Option<(u32, X25519PublicKey)> {
        self.otpk_public
    }

    /// Returns the optional one-time pre-key (OPK_pub) from this bundle.
    pub fn signature(&self) -> Signature {
        self.signature
    }

    pub fn try_from(
        ik_public: [u8; 32],
        signing_key_public: [u8; 32],
        spk_public: (u32, [u8; 32]),
        signature: [u8; 64],
        otpk_public: Option<(u32, [u8; 32])>,
    ) -> Result<Self, Error> {
        Ok(Self {
            ik_public: X25519PublicKey::from(ik_public),
            signing_key_public: VerifyingKey::from_bytes(&signing_key_public)
                .map_err(|err| Error::Serde(err.to_string()))?,
            spk_public: (spk_public.0, X25519PublicKey::from(spk_public.1)),
            signature: Signature::from_bytes(&SignatureBytes::from(signature)),
            otpk_public: otpk_public.map(|(id, otpk)| (id, X25519PublicKey::from(otpk))),
        })
    }
}

pub struct AccountPreKeyBundle {
    pub ik_public: X25519PublicKey,
    pub signing_key_public: VerifyingKey,
    pub spk_public: (u32, X25519PublicKey),
    pub signature: Signature,
    pub otpks_public: HashMap<u32, X25519PublicKey>,
}

impl From<&AccountPreKeyBundle> for SessionPreKeyBundle {
    fn from(value: &AccountPreKeyBundle) -> Self {
        Self {
            ik_public: value.ik_public,
            signing_key_public: value.signing_key_public,
            spk_public: (value.spk_public.0, value.spk_public.1),
            signature: value.signature,
            otpk_public: None,
        }
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
        let session_bundle = SessionPreKeyBundle::new(&identity_key, &pre_key, None);

        // Verify the bundle
        assert!(session_bundle.verify().is_ok());

        // Create another bundle with different keys
        let another_identity = IdentityKey::new();
        // let another_pre_key = SignedPreKey::new(100);

        // Try to create an invalid bundle (mixing keys)
        let invalid_bundle = SessionPreKeyBundle {
            ik_public: identity_key.dh_key_public(),
            signing_key_public: another_identity.signing_key_public(), // Wrong verify key
            spk_public: (pre_key.id(), pre_key.public_key()),
            signature: pre_key.signature(&identity_key),
            otpk_public: None,
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
        let encoded = pre_key.public_key().to_bytes();
        assert!(
            identity_key
                .signing_key_public()
                .verify(&encoded, &signature1)
                .is_ok()
        );
    }

    #[test]
    fn test_tamper_resistance() {
        let identity_key = IdentityKey::new();
        let pre_key = SignedPreKey::new(77);

        let mut bundle = SessionPreKeyBundle::new(&identity_key, &pre_key, None);

        // Tamper with the signed pre-key
        let another_pre_key = SignedPreKey::new(78);
        bundle.spk_public = (another_pre_key.id(), another_pre_key.public_key());

        // Verification should fail
        assert!(bundle.verify().is_err());
    }
}

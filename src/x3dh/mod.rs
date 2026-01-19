mod identity_key;

use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::{Signature, VerifyingKey};
pub use identity_key::*;
mod one_time_pre_key;
pub use one_time_pre_key::*;
mod pre_key;
pub use pre_key::*;

use crate::{Error, X25519PublicKey, X25519Secret};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SALT: &[u8] = b"Zealot-E2E-NaCl";

/// A shared secret derived from X3DH key agreement.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X3DHSharedSecret(pub(crate) Box<[u8; 32]>);

/// The result of an X3DH key agreement initiated by Alice.
///
/// Contains both the calculated shared secret and Alice's ephemeral public key
/// that needs to be transmitted to Bob.
pub struct X3DHInitializationResult {
    shared_secret: X3DHSharedSecret,
    ephemeral_public: X25519PublicKey,
}

impl X3DHInitializationResult {
    /// Returns the ephemeral public key that needs to be sent to the responder.
    pub fn public_key(&self) -> X25519PublicKey {
        self.ephemeral_public
    }

    /// Consumes the result and returns only the shared secret.
    ///
    /// This should be called only after the ephemeral public key has been
    /// transmitted to the responder.
    pub fn shared_secret(self) -> X3DHSharedSecret {
        self.shared_secret
    }
}

/// A bundle of public keys used for X3DH key agreement.
///
/// Contains all the public key material needed by another user to establish
/// a secure session asynchronously using the X3DH protocol:
/// - Identity key for authentication and key agreement
/// - Signed pre-key with signature for authenticated key agreement
/// - Optional one-time pre-key for additional security
pub struct X3DHPublicKeys {
    pub(crate) ik_public: X25519PublicKey,
    pub(crate) signing_key_public: VerifyingKey,
    pub(crate) spk_public: (u32, X25519PublicKey),
    pub(crate) signature: Signature,
    pub(crate) otpk_public: Option<(u32, X25519PublicKey)>,
}

impl X3DHPublicKeys {
    /// Creates a new pre-key bundle from the provided keys.
    #[allow(dead_code)]
    pub(crate) fn new(
        ik_public: X25519PublicKey,
        signing_key_public: VerifyingKey,
        signature: Signature,
        spk_public: (u32, X25519PublicKey),
        otpk: Option<(u32, X25519PublicKey)>,
    ) -> Self {
        Self {
            ik_public,
            signing_key_public,
            spk_public,
            signature,
            otpk_public: otpk,
        }
    }

    /// Verifies the bundle's signature to ensure authenticity.
    ///
    /// This verification confirms that the signed pre-key was actually created
    /// by the owner of the identity key.
    pub fn verify(&self) -> Result<(), Error> {
        let encoded_key = self.spk_public.1.to_bytes();
        self.signing_key_public
            .verify_strict(&encoded_key, &self.signature)
            .map_err(|err| Error::PreKey(err.to_string()))
    }

    /// Returns the public signed pre-key from this bundle.
    #[inline]
    pub fn spk_public(&self) -> (u32, X25519PublicKey) {
        self.spk_public
    }

    /// Returns the public identity key for DH operations.
    #[inline]
    pub fn ik_public(&self) -> X25519PublicKey {
        self.ik_public
    }

    /// Returns the public verification key for the identity.
    #[inline]
    pub fn signing_key_public(&self) -> VerifyingKey {
        self.signing_key_public
    }

    /// Returns the optional one-time pre-key from this bundle.
    #[inline]
    pub fn otpk_public(&self) -> Option<(u32, X25519PublicKey)> {
        self.otpk_public
    }

    /// Returns the signature for the signed pre-key.
    #[inline]
    pub fn signature(&self) -> Signature {
        self.signature
    }

    /// Creates a bundle from raw byte arrays.
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

/// Implementation of the X3DH (Extended Triple Diffie-Hellman) key agreement protocol.
///
/// X3DH enables two parties to establish a shared secret asynchronously, even if one
/// party is offline. The protocol combines multiple Diffie-Hellman exchanges to provide
/// strong security properties.
pub struct X3DH {
    info: Vec<u8>,
}

impl X3DH {
    /// Creates a new X3DH protocol instance with the specified application info.
    ///
    /// The info parameter is used as context for the HKDF key derivation, ensuring
    /// that keys derived in different contexts will be different even if the same
    /// key material is used.
    pub fn new(info: &[u8]) -> Self {
        Self {
            info: info.to_vec(),
        }
    }

    /// Initiates key agreement with a responder's pre-key bundle.
    ///
    /// This implements Alice's side of the X3DH protocol:
    /// 1. Verifies Bob's signed pre-key
    /// 2. Generates an ephemeral key pair
    /// 3. Performs the necessary DH computations
    /// 4. Derives the shared secret
    pub fn initiate_for_alice(
        &self,
        a_identity: &IdentityKey,
        b_bundle: &X3DHPublicKeys,
    ) -> Result<X3DHInitializationResult, Error> {
        b_bundle
            .verify()
            .map_err(|_| Error::PreKey("Failed to verify pre-key bundle".to_string()))?;

        let seed = generate_random_seed();
        let a_ephemeral = X25519Secret::from(seed);

        // DH1 = DH(IKa, SPKb)
        let dh1 = a_identity.dh(&b_bundle.spk_public().1);
        // DH2 = DH(EKa, IKb)
        let dh2 = a_ephemeral.dh(&b_bundle.ik_public());
        // DH3 = DH(EKa, SPKb)
        let dh3 = a_ephemeral.dh(&b_bundle.spk_public().1);
        // DH4 = DH(EKa, OPKb)
        let dh4_opt = b_bundle.otpk_public().map(|otpk| a_ephemeral.dh(&otpk.1));

        let shared_secret = self.calculate_shared_secret(dh1, dh2, dh3, dh4_opt)?;

        Ok(X3DHInitializationResult {
            shared_secret,
            ephemeral_public: a_ephemeral.public_key(),
        })
    }

    /// Processes an initiation message from the initiator (Alice).
    ///
    /// This implements Bob's side of the X3DH protocol by performing the same
    /// DH computations as Alice and deriving the same shared secret.
    pub fn initiate_for_bob(
        &self,
        b_identity: &IdentityKey,
        b_signed_pre_key: &SignedPreKey,
        b_one_time_pre_key: Option<OneTimePreKey>,
        a_identity_public: &X25519PublicKey,
        a_ephemeral_public: &X25519PublicKey,
    ) -> Result<X3DHSharedSecret, Error> {
        // DH1 = DH(SPKb, IKa)
        let dh1 = b_signed_pre_key.dh(a_identity_public);
        // DH2 = DH(IKb, EKa)
        let dh2 = b_identity.dh(a_ephemeral_public);
        // DH3 = DH(SPKb, EKa)
        let dh3 = b_signed_pre_key.dh(a_ephemeral_public);
        // DH4 = DH(OPKb, EKa)
        let dh4_opt: Option<Result<SharedSecret, Error>> = b_one_time_pre_key.map(|opk| {
            let result = opk.dh(a_ephemeral_public).map_err(|_| {
                Error::PreKey("Error performing DH with one-time pre-key".to_string())
            })?;
            Ok(result)
        });

        let dh4 = match dh4_opt {
            Some(result) => Some(result?),
            None => None,
        };

        self.calculate_shared_secret(dh1, dh2, dh3, dh4)
    }

    fn calculate_shared_secret(
        &self,
        dh1: SharedSecret,
        dh2: SharedSecret,
        dh3: SharedSecret,
        dh4: Option<SharedSecret>,
    ) -> Result<X3DHSharedSecret, Error> {
        // IKM = DH1 || DH2 || DH3 || DH4 (if available)
        let mut key_material = Box::new([0u8; 128]);

        key_material[0..32].copy_from_slice(dh1.as_bytes());
        key_material[32..64].copy_from_slice(dh2.as_bytes());
        key_material[64..96].copy_from_slice(dh3.as_bytes());
        if let Some(dh4) = dh4 {
            key_material[96..128].copy_from_slice(dh4.as_bytes());
        }

        let hkdf = Hkdf::<Sha256>::new(Some(SALT), &key_material.to_vec());
        key_material.zeroize();

        let mut shared_secret = Box::new([0u8; 32]);
        hkdf.expand(&self.info, shared_secret.as_mut_slice())
            .map_err(|_| Error::Crypto("HKDF expansion failed".to_string()))?;

        Ok(X3DHSharedSecret(shared_secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityKey, OneTimePreKey, SignedPreKey};

    #[test]
    fn test_x3dh_key_agreement() {
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);
        let bob_bundle = X3DHPublicKeys::new(
            bob_identity.dh_key_public(),
            bob_identity.signing_key_public(),
            bob_signed_pre_key.signature(&bob_identity),
            (bob_signed_pre_key.id(), bob_signed_pre_key.public_key()),
            Some((bob_one_time_pre_key.id(), bob_one_time_pre_key.public_key())),
        );

        // Verification is successful
        assert!(bob_bundle.verify().is_ok());

        // Create another bundle with different keys
        let another_identity = IdentityKey::new();

        // Try to create an invalid bundle (mixing keys)
        let invalid_bundle = X3DHPublicKeys::new(
            bob_identity.dh_key_public(),
            another_identity.signing_key_public(),
            bob_signed_pre_key.signature(&bob_identity),
            (bob_signed_pre_key.id(), bob_signed_pre_key.public_key()),
            None,
        );

        // This should fail verification
        assert!(invalid_bundle.verify().is_err());

        // Different protocol infos should produce different shared secrets
        let x3dh1 = X3DH::new(b"Protocol-Info-1");
        let alice_result_1 = x3dh1
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        let x3dh2 = X3DH::new(b"Protocol-Info-2");
        let alice_result_2 = x3dh2
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        assert_ne!(
            alice_result_1.shared_secret.0,
            alice_result_2.shared_secret.0
        );

        // Alice initiates the key agreement
        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        // Bob processes Alice's initiation
        let bob_secret = x3dh
            .initiate_for_bob(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.dh_key_public(),
                &alice_result.ephemeral_public,
            )
            .unwrap();

        assert_eq!(alice_result.shared_secret.0, bob_secret.0);
    }

    #[test]
    fn test_x3dh_agreement_without_one_time_key() {
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_bundle = X3DHPublicKeys::new(
            bob_identity.dh_key_public(),
            bob_identity.signing_key_public(),
            bob_signed_pre_key.signature(&bob_identity),
            (bob_signed_pre_key.id(), bob_signed_pre_key.public_key()),
            None,
        );

        let x3dh = X3DH::new(b"Test-Protocol-Info");
        let alice_result = x3dh
            .initiate_for_alice(&alice_identity, &bob_bundle)
            .unwrap();

        let bob_secret = x3dh
            .initiate_for_bob(
                &bob_identity,
                &bob_signed_pre_key,
                None,
                &alice_identity.dh_key_public(),
                &alice_result.ephemeral_public,
            )
            .unwrap();

        assert_eq!(alice_result.shared_secret.0, bob_secret.0);
    }
}

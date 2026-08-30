use std::sync::OnceLock;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A public key for X25519 elliptic curve Diffie-Hellman key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(PublicKey);

impl X25519PublicKey {
    /// Returns the public key as a byte array reference.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Returns the public key as an owned byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<[u8; 32]> for X25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }
}

impl From<PublicKey> for X25519PublicKey {
    fn from(value: PublicKey) -> Self {
        Self(value)
    }
}

impl AsRef<PublicKey> for X25519PublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

#[derive(Clone)]
pub struct X25519Secret {
    secret: Box<StaticSecret>,
    public: OnceLock<X25519PublicKey>,
}

impl X25519Secret {
    #[inline]
    pub(crate) fn dh(&self, public_key: &X25519PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(public_key.as_ref())
    }

    pub(crate) fn public_key(&self) -> X25519PublicKey {
        *self
            .public
            .get_or_init(|| PublicKey::from(self.secret.as_ref()).into())
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.secret.as_bytes()
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

impl From<[u8; 32]> for X25519Secret {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            secret: Box::new(StaticSecret::from(bytes)),
            public: OnceLock::new(),
        }
    }
}

impl From<Box<[u8; 32]>> for X25519Secret {
    fn from(mut bytes: Box<[u8; 32]>) -> Self {
        let secret = StaticSecret::from(*bytes);
        bytes.zeroize();
        Self {
            secret: Box::new(secret),
            public: OnceLock::new(),
        }
    }
}

impl AsRef<StaticSecret> for X25519Secret {
    fn as_ref(&self) -> &StaticSecret {
        &self.secret
    }
}

impl Zeroize for X25519Secret {
    fn zeroize(&mut self) {
        *self.secret = StaticSecret::from([0u8; 32]);
        self.public = OnceLock::new();
    }
}

impl ZeroizeOnDrop for X25519Secret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_zeroize_clears_key_material() {
        let mut secret = X25519Secret::from([7u8; 32]);
        assert_eq!(secret.as_bytes(), &[7u8; 32]);

        secret.zeroize();

        assert_eq!(
            secret.as_bytes(),
            &[0u8; 32],
            "zeroize must clear the secret bytes"
        );
    }

    #[test]
    fn test_cached_public_key_matches_uncached_derivation() {
        let secret = X25519Secret::from([11u8; 32]);
        let expected = PublicKey::from(secret.as_ref());

        // First call populates the cache, later calls must return the same value.
        assert_eq!(secret.public_key().as_bytes(), expected.as_bytes());
        assert_eq!(secret.public_key().as_bytes(), expected.as_bytes());

        // A clone carries the cache but represents the same secret.
        let cloned = secret.clone();
        assert_eq!(cloned.public_key().as_bytes(), expected.as_bytes());
    }

    #[test]
    fn test_zeroize_drops_cached_public_key() {
        let mut secret = X25519Secret::from([11u8; 32]);
        let before = secret.public_key().to_bytes();

        secret.zeroize();

        let after = secret.public_key().to_bytes();
        assert_ne!(before, after, "stale public key survived zeroize");
        assert_eq!(
            after,
            PublicKey::from(secret.as_ref()).to_bytes(),
            "public key must match the zeroized secret"
        );
    }
}

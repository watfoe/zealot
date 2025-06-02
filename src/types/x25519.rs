use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// TODO: Add documentation here
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(PublicKey);

impl X25519PublicKey {
    /// TODO: Add documentation here
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// TODO: Add documentation here
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

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(Box<StaticSecret>);

impl X25519Secret {
    pub(crate) fn dh(&self, public_key: &X25519PublicKey) -> SharedSecret {
        self.0.diffie_hellman(public_key.as_ref())
    }

    pub(crate) fn public_key(&self) -> X25519PublicKey {
        let pub_key = PublicKey::from(self.0.as_ref());
        pub_key.into()
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<[u8; 32]> for X25519Secret {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Box::new(StaticSecret::from(bytes)))
    }
}

impl From<Box<[u8; 32]>> for X25519Secret {
    fn from(mut bytes: Box<[u8; 32]>) -> Self {
        let secret = StaticSecret::from(*bytes);
        bytes.zeroize();
        Self(Box::new(secret))
    }
}

impl AsRef<StaticSecret> for X25519Secret {
    fn as_ref(&self) -> &StaticSecret {
        &self.0
    }
}

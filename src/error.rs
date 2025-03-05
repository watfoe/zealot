#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("Protocol Violation: {0}")]
    Protocol(String),

    #[error("Session state error")]
    Session,

    #[error("Identity key error")]
    Identity(String),

    #[error("Pre-key error")]
    PreKey(String),

    #[error("Random number generation failed")]
    Random,

    #[error("Serialization/deserialization failed: {0}")]
    Serde(String),
}

impl From<aes_gcm::Error> for Error {
    fn from(value: aes_gcm::Error) -> Self {
        Self::Crypto(value.to_string())
    }
}

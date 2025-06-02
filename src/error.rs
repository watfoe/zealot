/// Errors that can occur during Signal Protocol operations.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// A cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    /// A protocol rule was violated.
    #[error("Protocol Violation: {0}")]
    Protocol(String),

    /// Session is in an invalid state.
    #[error("Session state error")]
    Session,

    /// Identity key operation failed.
    #[error("Identity key error")]
    Identity(String),

    /// Pre-key operation failed.
    #[error("Pre-key error")]
    PreKey(String),

    /// Random number generation failed.
    #[error("Random number generation failed")]
    Random,

    /// Serialization or deserialization failed.
    #[error("Serialization/deserialization failed: {0}")]
    Serde(String),
}

impl From<aes_gcm_siv::Error> for Error {
    fn from(value: aes_gcm_siv::Error) -> Self {
        Self::Crypto(value.to_string())
    }
}

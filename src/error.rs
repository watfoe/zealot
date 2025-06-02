/// TODO: Add documentation here
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// TODO: Add documentation here
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    /// TODO: Add documentation here
    #[error("Protocol Violation: {0}")]
    Protocol(String),

    /// TODO: Add documentation here
    #[error("Session state error")]
    Session,

    /// TODO: Add documentation here
    #[error("Identity key error")]
    Identity(String),

    /// TODO: Add documentation here
    #[error("Pre-key error")]
    PreKey(String),

    /// TODO: Add documentation here
    #[error("Random number generation failed")]
    Random,

    /// TODO: Add documentation here
    #[error("Serialization/deserialization failed: {0}")]
    Serde(String),
}

impl From<aes_gcm_siv::Error> for Error {
    fn from(value: aes_gcm_siv::Error) -> Self {
        Self::Crypto(value.to_string())
    }
}

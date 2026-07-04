/// Errors that can occur during Signal Protocol operations.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// A cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    /// A protocol rule was violated.
    #[error("Protocol Violation: {0}")]
    Protocol(String),

    /// A message header could not be decrypted with the current or next
    /// receiving header key.
    ///
    /// Usually benign: a replayed message, a message belonging to a different
    /// or already-rotated session, or random garbage. Callers should normally
    /// drop the message. Persistent mismatches can indicate the peer is using a
    /// session this side no longer holds and a new session should be negotiated.
    #[error("Message header does not match the current or next receiving header key")]
    HeaderKeyMismatch,

    /// A message whose number was already processed on its chain was received
    /// again.
    ///
    /// A duplicate or late re-delivery; callers should drop it.
    #[error("Message was already processed (duplicate or delayed)")]
    DuplicateMessage,

    /// Decrypting a message would require skipping more messages than
    /// `max_skip` permits.
    ///
    /// Callers should drop the message. A large gap may signal heavy loss or an
    /// attempt to exhaust the skipped-message-key store.
    #[error("Too many skipped messages")]
    TooManySkipped,

    /// The message header authenticated but the message body failed
    /// authenticated decryption.
    ///
    /// Indicates a corrupted or tampered ciphertext; callers should drop it.
    #[error("Message decryption failed")]
    MessageDecryptionFailed,

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

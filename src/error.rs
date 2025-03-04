use rand_core::OsError;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);

impl From<aes_gcm::Error> for Error {
    fn from(value: aes_gcm::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<OsError> for Error {
    fn from(value: OsError) -> Self {
        Self(value.to_string())
    }
}

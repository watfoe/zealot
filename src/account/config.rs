/// Configuration parameters for an Account.
#[derive(Clone, Debug)]
pub struct AccountConfig {
    /// Maximum number of out-of-order messages to handle.
    pub max_skipped_messages: u32,
    /// How often to rotate the signed pre-key.
    pub spk_rotation_interval: std::time::Duration,
    /// Minimum number of one-time pre-keys to maintain.
    pub min_otpks: usize,
    /// Maximum number of one-time pre-keys to store.
    pub max_otpks: usize,
    /// Maximum number of signed pre-keys to keep.
    pub max_spks: usize,
    /// Application-specific protocol identifier for key derivation.
    pub protocol_info: Vec<u8>,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            max_skipped_messages: 45,
            spk_rotation_interval: std::time::Duration::from_secs(7 * 24 * 60 * 60), // 1 week
            min_otpks: 8,
            max_otpks: 55,
            max_spks: 8,
            protocol_info: b"Zealot-E2E-Fe2O3".to_vec(),
        }
    }
}

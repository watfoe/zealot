/// TODO: Add documentation here
#[derive(Clone, Debug)]
pub struct AccountConfig {
    /// TODO: Add documentation here
    pub max_skipped_messages: u32,
    /// TODO: Add documentation here
    pub spk_rotation_interval: std::time::Duration,
    /// TODO: Add documentation here
    pub min_otpks: usize,
    /// TODO: Add documentation here
    pub max_otpks: usize,
    /// TODO: Add documentation here
    pub max_spks: usize,
    /// TODO: Add documentation here
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

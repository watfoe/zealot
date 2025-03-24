#[derive(Clone, Debug)]
pub struct AccountConfig {
    pub max_skipped_messages: u32,
    pub spk_rotation_interval: std::time::Duration,
    pub min_otpks: usize,
    pub max_otpks: usize,
    pub max_spks: usize,
    pub protocol_info: Vec<u8>,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            max_skipped_messages: 100,
            spk_rotation_interval: std::time::Duration::from_secs(7 * 24 * 60 * 60), // 1 week
            min_otpks: 20,
            max_otpks: 100,
            max_spks: 50,
            protocol_info: b"Zealot-E2E-v1".to_vec(),
        }
    }
}

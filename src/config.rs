#[derive(Clone, Debug)]
pub struct AccountConfig {
    pub max_skipped_messages: u32,
    pub signed_pre_key_rotation_interval: std::time::Duration,
    pub min_one_time_pre_keys: usize,
    pub max_one_time_pre_keys: usize,
    pub protocol_info: Vec<u8>,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            max_skipped_messages: 100,
            signed_pre_key_rotation_interval: std::time::Duration::from_secs(7 * 24 * 60 * 60), // 1 week
            min_one_time_pre_keys: 20,
            max_one_time_pre_keys: 100,
            protocol_info: b"Zealot-E2E-v1".to_vec(),
        }
    }
}

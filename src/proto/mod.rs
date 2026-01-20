use crate::ratchet::{Chain, RatchetState};
use crate::types::X25519Secret;
use crate::{
    Account, AccountConfig, DoubleRatchet, Error, IdentityKey, OneTimePreKey,
    OutboundSessionX3DHKeys, Session, SignedPreKey, X25519PublicKey,
};
use prost::Message;
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

include!(concat!(env!("OUT_DIR"), "/zealot.rs"));

impl Account {
    /// Serialize the account to Protocol Buffers format
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let ik_bytes = self.ik.to_bytes();
        let spk_rotation_secs = self
            .spk_last_rotation
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut spk_keys = HashMap::with_capacity(self.spk_store.keys.len());
        for (id, key) in self.spk_store.keys.iter() {
            spk_keys.insert(*id, key.to_bytes().to_vec());
        }

        let spk_store = SignedPreKeyStoreProto {
            next_id: self.spk_store.next_id,
            max_keys: self.spk_store.max_keys as u64,
            keys: spk_keys,
        };

        let mut otpk_keys = HashMap::with_capacity(self.otpk_store.count());
        for (id, key) in self.otpk_store.keys.iter() {
            otpk_keys.insert(*id, key.to_bytes().to_vec());
        }

        let otpk_store = OneTimePreKeyStoreProto {
            next_id: self.otpk_store.next_id,
            max_keys: self.otpk_store.max_keys as u64,
            keys: otpk_keys,
        };

        let config = AccountConfigProto {
            max_skipped_messages: self.config().max_skipped_messages,
            spk_rotation_interval_secs: self.config().spk_rotation_interval.as_secs(),
            min_otpks: self.config().min_otpks as u64,
            max_otpks: self.config().max_otpks as u64,
            max_spks: self.config().max_spks as u64,
            protocol_info: self.config().protocol_info.clone(),
        };

        let account_proto = AccountProto {
            version: 1, // Current schema version
            ik: ik_bytes.to_vec(),
            spk_store: Some(spk_store),
            spk_last_rotation: spk_rotation_secs,
            otpk_store: Some(otpk_store),
            config: Some(config),
        };

        let mut buf = Vec::new();
        account_proto
            .encode(&mut buf)
            .map_err(|err| Error::Serde(format!("Failed to encode account: {err:?}")))?;

        Ok(buf)
    }

    /// Deserialize an account from Protocol Buffers format
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let account_proto = AccountProto::decode(bytes)
            .map_err(|err| Error::Serde(format!("Failed to decode account: {err:?}")))?;

        if account_proto.version != 1 {
            return Err(Error::Serde(format!(
                "Unsupported schema version: {}",
                account_proto.version
            )));
        }

        if account_proto.ik.len() != 64 {
            return Err(Error::Serde("Invalid identity key length".to_string()));
        }
        let mut ik_bytes = [0u8; 64];
        ik_bytes.copy_from_slice(&account_proto.ik);
        let ik = IdentityKey::from(ik_bytes);

        let config = if let Some(config_proto) = account_proto.config {
            AccountConfig {
                max_skipped_messages: config_proto.max_skipped_messages,
                spk_rotation_interval: Duration::from_secs(config_proto.spk_rotation_interval_secs),
                min_otpks: config_proto.min_otpks as usize,
                max_otpks: config_proto.max_otpks as usize,
                max_spks: config_proto.max_spks as usize,
                protocol_info: config_proto.protocol_info,
            }
        } else {
            return Err(Error::Serde("Missing account config".to_string()));
        };

        let spk_store = if let Some(store) = account_proto.spk_store {
            let mut keys = HashMap::with_capacity(store.max_keys as usize);
            for (id, key_bytes) in store.keys {
                if key_bytes.len() != 36 {
                    return Err(Error::Serde("Invalid signed pre-key length".to_string()));
                }
                let mut spk_bytes = [0u8; 36];
                spk_bytes.copy_from_slice(&key_bytes);
                let spk = SignedPreKey::from(spk_bytes);
                keys.insert(id, spk);
            }

            crate::SignedPreKeyStore {
                keys,
                next_id: store.next_id,
                max_keys: store.max_keys as usize,
            }
        } else {
            return Err(Error::Serde("Missing signed-pre-key store".to_string()));
        };

        let spk_last_rotation = UNIX_EPOCH + Duration::from_secs(account_proto.spk_last_rotation);

        let otpk_store = if let Some(store) = account_proto.otpk_store {
            let mut keys = HashMap::with_capacity(config.max_otpks);
            for (id, key_bytes) in store.keys {
                if key_bytes.len() != 37 {
                    return Err(Error::Serde("Invalid one-time pre-key length".to_string()));
                }
                let mut otpk_bytes = [0u8; 37];
                otpk_bytes.copy_from_slice(&key_bytes);
                keys.insert(id, OneTimePreKey::from(otpk_bytes));
            }

            crate::OneTimePreKeyStore {
                keys,
                next_id: store.next_id,
                max_keys: store.max_keys as usize,
            }
        } else {
            return Err(Error::Serde("Missing one-time pre-key store".to_string()));
        };

        Ok(Account {
            ik,
            spk_store,
            spk_last_rotation,
            otpk_store,
            config,
        })
    }
}

impl Session {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let session_proto = SessionProto {
            session_id: self.session_id.clone(),
            ratchet: Some(serialize_ratchet(&self.ratchet)),
            x3dh_keys: self.x3dh_keys.as_ref().map(|keys| keys.serialize()),
        };

        let mut buf = Vec::new();
        session_proto
            .encode(&mut buf)
            .map_err(|err| Error::Serde(format!("Failed to encode session: {err:?}")))?;

        Ok(buf)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let session_proto = SessionProto::decode(bytes)
            .map_err(|err| Error::Serde(format!("Failed to decode session: {err:?}")))?;

        let ratchet = if let Some(ratchet_proto) = session_proto.ratchet {
            deserialize_ratchet(ratchet_proto)?
        } else {
            return Err(Error::Serde("Missing ratchet data".to_string()));
        };

        let x3dh_keys = if let Some(x3dh_keys_proto) = session_proto.x3dh_keys {
            Some(OutboundSessionX3DHKeys::deserialize(x3dh_keys_proto)?)
        } else {
            None
        };

        Ok(Session {
            session_id: session_proto.session_id,
            ratchet,
            x3dh_keys,
        })
    }
}

impl OutboundSessionX3DHKeys {
    pub fn serialize(&self) -> OutboundSessionX3dhKeysProto {
        OutboundSessionX3dhKeysProto {
            spk_id: self.spk_id,
            otpk_id: self.otpk_id,
            ephemeral_key_public: self.ephemeral_key_public.to_bytes().to_vec(),
        }
    }

    pub fn deserialize(proto: OutboundSessionX3dhKeysProto) -> Result<Self, Error> {
        if proto.ephemeral_key_public.len() != 32 {
            return Err(Error::Serde(
                "Invalid Ephemeral public key length".to_string(),
            ));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&proto.ephemeral_key_public);

        Ok(OutboundSessionX3DHKeys {
            spk_id: proto.spk_id,
            otpk_id: proto.otpk_id,
            ephemeral_key_public: X25519PublicKey::from(bytes),
        })
    }
}

fn serialize_ratchet(ratchet: &DoubleRatchet) -> RatchetProto {
    let dh_pair_bytes = ratchet.state.dh_pair.to_bytes().to_vec();

    let state_proto = RatchetStateProto {
        remote_dh_key_public: match &ratchet.state.remote_dh_key_public {
            Some(pk) => pk.as_bytes().to_vec(),
            None => Vec::new(),
        },
        root_key: ratchet.state.root_key.to_vec(),
        sending_chain: Some(ChainProto {
            chain_key: ratchet.state.sending_chain.chain_key.to_vec(),
            index: ratchet.state.sending_chain.index,
        }),
        receiving_chain: Some(ChainProto {
            chain_key: ratchet.state.receiving_chain.chain_key.to_vec(),
            index: ratchet.state.receiving_chain.index,
        }),
        previous_sending_chain_length: ratchet.state.previous_sending_chain_length,
        sending_message_number: ratchet.state.sending_message_number,
        receiving_message_number: ratchet.state.receiving_message_number,
        sending_header_key: match &ratchet.state.sending_header_key {
            Some(key) => key.to_vec(),
            None => Vec::new(),
        },
        receiving_header_key: match &ratchet.state.receiving_header_key {
            Some(key) => key.to_vec(),
            None => Vec::new(),
        },
        next_sending_header_key: ratchet.state.next_sending_header_key.to_vec(),
        next_receiving_header_key: match &ratchet.state.next_receiving_header_key {
            Some(key) => key.to_vec(),
            None => Vec::new(),
        },
        ad: ratchet.state.ad.to_vec(),
    };

    let mut skipped_keys = Vec::new();
    for ((header_key, message_number), message_key) in &ratchet.skipped_message_keys {
        skipped_keys.push(SkippedMessageKeyProto {
            header_key: header_key.to_vec(),
            message_number: *message_number,
            message_key: message_key.to_vec(),
        });
    }

    RatchetProto {
        dh_pair: dh_pair_bytes,
        state: Some(state_proto),
        skipped_message_keys: skipped_keys,
        max_skip: ratchet.max_skip,
    }
}

fn deserialize_ratchet(proto: RatchetProto) -> Result<DoubleRatchet, Error> {
    if proto.dh_pair.len() != 32 {
        return Err(Error::Serde("Invalid DH key pair length".to_string()));
    }

    let mut dh_pair_bytes = [0u8; 32];
    dh_pair_bytes.copy_from_slice(&proto.dh_pair);
    let dh_pair = X25519Secret::from(dh_pair_bytes);

    let state_proto = proto
        .state
        .ok_or_else(|| Error::Serde("Missing ratchet state".to_string()))?;

    let remote_dh_key_public = if !state_proto.remote_dh_key_public.is_empty() {
        if state_proto.remote_dh_key_public.len() != 32 {
            return Err(Error::Serde("Invalid remote public key length".to_string()));
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&state_proto.remote_dh_key_public);
        Some(X25519PublicKey::from(pk_bytes))
    } else {
        None
    };

    if state_proto.root_key.len() != 32 {
        return Err(Error::Serde("Invalid root key length".to_string()));
    }
    let mut root_key = Box::new([0u8; 32]);
    root_key.copy_from_slice(&state_proto.root_key);

    if state_proto.ad.len() != 64 {
        return Err(Error::Serde("Invalid associated data length".to_string()));
    }
    let mut ad = Box::new([0u8; 64]);
    ad.copy_from_slice(&state_proto.ad);

    let sending_chain_proto = state_proto
        .sending_chain
        .ok_or_else(|| Error::Serde("Missing sending chain".to_string()))?;
    let receiving_chain_proto = state_proto
        .receiving_chain
        .ok_or_else(|| Error::Serde("Missing receiving chain".to_string()))?;

    if sending_chain_proto.chain_key.len() != 32 || receiving_chain_proto.chain_key.len() != 32 {
        return Err(Error::Serde("Invalid chain key length".to_string()));
    }

    let mut sending_chain_key = Box::new([0u8; 32]);
    let mut receiving_chain_key = Box::new([0u8; 32]);
    sending_chain_key.copy_from_slice(&sending_chain_proto.chain_key);
    receiving_chain_key.copy_from_slice(&receiving_chain_proto.chain_key);

    let mut sending_chain = Chain::new(sending_chain_key);
    sending_chain.set_index(sending_chain_proto.index);
    let mut receiving_chain = Chain::new(receiving_chain_key);
    receiving_chain.set_index(receiving_chain_proto.index);

    let sending_header_key = if !state_proto.sending_header_key.is_empty() {
        if state_proto.sending_header_key.len() != 32 {
            return Err(Error::Serde(
                "Invalid sending header key length".to_string(),
            ));
        }
        let mut key = Box::new([0u8; 32]);
        key.copy_from_slice(&state_proto.sending_header_key);
        Some(key)
    } else {
        None
    };

    let receiving_header_key = if !state_proto.receiving_header_key.is_empty() {
        if state_proto.receiving_header_key.len() != 32 {
            return Err(Error::Serde(
                "Invalid receiving header key length".to_string(),
            ));
        }
        let mut key = Box::new([0u8; 32]);
        key.copy_from_slice(&state_proto.receiving_header_key);
        Some(key)
    } else {
        None
    };

    if state_proto.next_sending_header_key.len() != 32 {
        return Err(Error::Serde(
            "Invalid next sending header key length".to_string(),
        ));
    }
    let mut next_sending_header_key = Box::new([0u8; 32]);
    next_sending_header_key.copy_from_slice(&state_proto.next_sending_header_key);

    let next_receiving_header_key = if !state_proto.next_receiving_header_key.is_empty() {
        if state_proto.next_receiving_header_key.len() != 32 {
            return Err(Error::Serde(
                "Invalid next receiving header key length".to_string(),
            ));
        }
        let mut key = Box::new([0u8; 32]);
        key.copy_from_slice(&state_proto.next_receiving_header_key);
        Some(key)
    } else {
        None
    };

    let state = RatchetState {
        ad,
        dh_pair,
        remote_dh_key_public,
        root_key,
        sending_chain,
        receiving_chain,
        previous_sending_chain_length: state_proto.previous_sending_chain_length,
        sending_message_number: state_proto.sending_message_number,
        receiving_message_number: state_proto.receiving_message_number,
        sending_header_key,
        receiving_header_key,
        next_sending_header_key,
        next_receiving_header_key,
    };

    let mut skipped_message_keys = HashMap::new();
    for key in proto.skipped_message_keys {
        let mut header_key = Box::new([0u8; 32]);
        header_key.copy_from_slice(&key.header_key);

        let mut message_key = Box::new([0u8; 32]);
        message_key.copy_from_slice(&key.message_key);

        skipped_message_keys.insert((header_key, key.message_number), message_key);
    }

    Ok(DoubleRatchet {
        state,
        skipped_message_keys,
        max_skip: proto.max_skip,
    })
}

#[cfg(test)]
mod tests {
    use crate::{Account, AccountConfig, Session, X3DHPublicKeys};
    use std::time::Duration;

    #[test]
    fn test_account_serialization_roundtrip() {
        let config = AccountConfig {
            max_skipped_messages: 25,
            spk_rotation_interval: Duration::from_secs(24 * 60 * 60 * 3), // 3 days
            min_otpks: 15,
            max_otpks: 75,
            max_spks: 20,
            protocol_info: b"Test-Protocol".to_vec(),
        };
        let account = Account::new(Some(config));

        let serialized = account.serialize().unwrap();
        let deserialized = Account::deserialize(&serialized).unwrap();

        // Verify core functionality is preserved
        assert_eq!(
            account.ik_public().as_bytes(),
            deserialized.ik_public().as_bytes()
        );
        assert_eq!(
            account.config().protocol_info,
            deserialized.config().protocol_info
        );
        assert_eq!(account.otpk_store.count(), deserialized.otpk_store.count());
    }

    #[test]
    fn test_session_serialization_preserves_functionality() {
        let (mut alice_session, mut bob_session) = create_test_session_pair();

        // Exchange messages before serialization
        let message1 = "Hello before serialization";
        let encrypted1 = alice_session.encrypt(message1.as_bytes()).unwrap();
        let decrypted1 = bob_session.decrypt(&encrypted1).unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), message1);

        // Serialize both sessions
        let alice_serialized = alice_session.serialize().unwrap();
        let bob_serialized = bob_session.serialize().unwrap();

        let mut alice_restored = Session::deserialize(&alice_serialized).unwrap();
        let mut bob_restored = Session::deserialize(&bob_serialized).unwrap();

        // Verify sessions work after restoration
        let message2 = "Hello after serialization";
        let encrypted2 = alice_restored.encrypt(message2.as_bytes()).unwrap();
        let decrypted2 = bob_restored.decrypt(&encrypted2).unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), message2);
    }

    #[test]
    fn test_out_of_order_messages_with_serialization() {
        let (mut alice_session, mut bob_session) = create_test_session_pair();

        // Alice sends multiple messages
        let messages = ["Message 1", "Message 2", "Message 3"];
        let encrypted_messages: Vec<_> = messages
            .iter()
            .map(|msg| alice_session.encrypt(msg.as_bytes()).unwrap())
            .collect();

        // Bob receives first message
        let _ = bob_session.decrypt(&encrypted_messages[0]).unwrap();

        // Serialize Bob's session with pending messages
        let bob_serialized = bob_session.serialize().unwrap();
        let mut bob_restored = Session::deserialize(&bob_serialized).unwrap();

        // Receive messages out of order in restored session
        let decrypted3 = bob_restored.decrypt(&encrypted_messages[2]).unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), messages[2]);

        let decrypted2 = bob_restored.decrypt(&encrypted_messages[1]).unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), messages[1]);
    }

    #[test]
    fn test_session_x3dh_keys_lifecycle() {
        let alice_account = Account::new(None);
        let bob_account = Account::new(None);
        let bob_bundle = bob_account.prekey_bundle();
        let bob_x3dh_keys = X3DHPublicKeys::from(&bob_bundle);

        let session = alice_account
            .create_outbound_session(&bob_x3dh_keys)
            .unwrap();

        // Session should have X3DH keys initially
        assert!(session.x3dh_keys.is_some());

        let serialized = session.serialize().unwrap();
        let mut restored_session = Session::deserialize(&serialized).unwrap();

        // Mark as established and verify keys are cleared
        restored_session.mark_as_established();
        assert!(restored_session.x3dh_keys.is_none());
    }

    fn create_test_session_pair() -> (Session, Session) {
        let alice_account = Account::new(None);
        let mut bob_account = Account::new(None);

        let bob_bundle = bob_account.prekey_bundle();
        let bob_x3dh_keys = X3DHPublicKeys::from(&bob_bundle);

        let alice_session = alice_account
            .create_outbound_session(&bob_x3dh_keys)
            .unwrap();
        let outbound_x3dh_keys = alice_session.x3dh_keys.as_ref().unwrap();

        let bob_session = bob_account
            .create_inbound_session(&alice_account.ik_public(), &outbound_x3dh_keys)
            .unwrap();

        (alice_session, bob_session)
    }
}

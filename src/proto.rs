use crate::chain::Chain;
use crate::state::RatchetState;
use crate::{
    Account, AccountConfig, DoubleRatchet, Error, IdentityKey, OneTimePreKey, Session, SignedPreKey,
};
use prost::Message;
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

include!(concat!(env!("OUT_DIR"), "/zealot.rs"));

impl Account {
    /// Serialize the account to Protocol Buffers format
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let ik_bytes = self.ik.to_bytes();
        let spk_bytes = self.spk.to_bytes();
        let spk_rotation_secs = self
            .spk_last_rotation
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut otpk_keys = HashMap::new();
        for (id, key) in self.otpk_store.keys.iter() {
            otpk_keys.insert(*id, key.to_bytes().to_vec());
        }

        let otpk_store = OneTimePreKeyStoreProto {
            next_id: self.otpk_store.next_id,
            max_keys: self.otpk_store.max_keys as u32,
            keys: otpk_keys,
        };

        let config = AccountConfigProto {
            max_skipped_messages: self.config.max_skipped_messages,
            signed_pre_key_rotation_interval_secs: self
                .config
                .signed_pre_key_rotation_interval
                .as_secs(),
            min_one_time_pre_keys: self.config.min_one_time_pre_keys as u32,
            max_one_time_pre_keys: self.config.max_one_time_pre_keys as u32,
            protocol_info: self.config.protocol_info.clone(),
            kdf_info: self.config.kdf_info.clone(),
        };

        let mut sessions = HashMap::new();
        for (id, session) in &self.sessions {
            sessions.insert(id.clone(), session.serialize()?);
        }

        let account_proto = AccountProto {
            identity_key: ik_bytes.to_vec(),
            signed_pre_key: spk_bytes.to_vec(),
            spk_last_rotation: spk_rotation_secs,
            otpk_store: Some(otpk_store),
            sessions,
            config: Some(config),
            version: 1, // Current schema version
        };

        let mut buf = Vec::new();
        account_proto
            .encode(&mut buf)
            .map_err(|e| Error::Serde(format!("Failed to encode account: {}", e)))?;

        Ok(buf)
    }

    /// Deserialize an account from Protocol Buffers format
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let account_proto = AccountProto::decode(bytes)
            .map_err(|e| Error::Serde(format!("Failed to decode account: {}", e)))?;

        if account_proto.version != 1 {
            return Err(Error::Serde(format!(
                "Unsupported schema version: {}",
                account_proto.version
            )));
        }

        if account_proto.identity_key.len() != 64 {
            return Err(Error::Serde("Invalid identity key length".to_string()));
        }
        let mut ik_bytes = [0u8; 64];
        ik_bytes.copy_from_slice(&account_proto.identity_key);
        let ik = IdentityKey::from(ik_bytes);

        if account_proto.signed_pre_key.len() != 44 {
            return Err(Error::Serde("Invalid signed pre-key length".to_string()));
        }
        let mut spk_bytes = [0u8; 44];
        spk_bytes.copy_from_slice(&account_proto.signed_pre_key);
        let spk = SignedPreKey::from(spk_bytes);

        let spk_last_rotation = UNIX_EPOCH + Duration::from_secs(account_proto.spk_last_rotation);

        let otpk_store = if let Some(store) = account_proto.otpk_store {
            let mut keys = HashMap::new();
            for (id, key_bytes) in store.keys {
                if key_bytes.len() != 45 {
                    return Err(Error::Serde("Invalid one-time pre-key length".to_string()));
                }
                let mut otpk_bytes = [0u8; 45];
                otpk_bytes.copy_from_slice(&key_bytes);
                keys.insert(id, OneTimePreKey::from(otpk_bytes));
            }

            crate::one_time_pre_key::OneTimePreKeyStore {
                keys,
                next_id: store.next_id,
                max_keys: store.max_keys as usize,
            }
        } else {
            return Err(Error::Serde("Missing one-time pre-key store".to_string()));
        };

        let config = if let Some(config_proto) = account_proto.config {
            AccountConfig {
                max_skipped_messages: config_proto.max_skipped_messages,
                signed_pre_key_rotation_interval: Duration::from_secs(
                    config_proto.signed_pre_key_rotation_interval_secs,
                ),
                min_one_time_pre_keys: config_proto.min_one_time_pre_keys as usize,
                max_one_time_pre_keys: config_proto.max_one_time_pre_keys as usize,
                protocol_info: config_proto.protocol_info,
                kdf_info: config_proto.kdf_info,
            }
        } else {
            return Err(Error::Serde("Missing account config".to_string()));
        };

        let mut sessions = HashMap::new();
        for (id, session_proto) in account_proto.sessions {
            sessions.insert(id, Session::deserialize(session_proto)?);
        }

        Ok(Account {
            ik,
            spk,
            spk_last_rotation,
            otpk_store,
            sessions,
            config,
        })
    }
}

impl Session {
    pub fn serialize(&self) -> Result<SessionProto, Error> {
        let created_at_secs = self
            .created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_used_at_secs = self
            .last_used_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(SessionProto {
            session_id: self.session_id.clone(),
            ratchet: Some(serialize_ratchet(&self.ratchet)?),
            created_at: created_at_secs,
            last_used_at: last_used_at_secs,
            is_initiator: self.is_initiator,
        })
    }

    pub fn deserialize(proto: SessionProto) -> Result<Self, Error> {
        let ratchet = if let Some(ratchet_proto) = proto.ratchet {
            deserialize_ratchet(ratchet_proto)?
        } else {
            return Err(Error::Serde("Missing ratchet data".to_string()));
        };

        let created_at = UNIX_EPOCH + Duration::from_secs(proto.created_at);
        let last_used_at = UNIX_EPOCH + Duration::from_secs(proto.last_used_at);

        Ok(Session {
            session_id: proto.session_id,
            ratchet,
            created_at,
            last_used_at,
            is_initiator: proto.is_initiator,
        })
    }
}

fn serialize_ratchet(ratchet: &DoubleRatchet) -> Result<RatchetProto, Error> {
    let dh_pair_bytes = ratchet.state.dh_pair.to_bytes().to_vec();

    let state_proto = RatchetStateProto {
        dh_remote_public: match &ratchet.state.dh_remote_public {
            Some(pk) => pk.as_bytes().to_vec(),
            None => Vec::new(),
        },
        root_key: ratchet.state.root_key.to_vec(),
        sending_chain: Some(ChainProto {
            chain_key: ratchet.state.sending_chain.chain_key.to_vec(),
            index: ratchet.state.sending_chain.get_index(),
        }),
        receiving_chain: Some(ChainProto {
            chain_key: ratchet.state.receiving_chain.chain_key.to_vec(),
            index: ratchet.state.receiving_chain.get_index(),
        }),
        previous_sending_chain_length: ratchet.state.previous_sending_chain_length,
        sending_message_number: ratchet.state.sending_message_number,
        receiving_message_number: ratchet.state.receiving_message_number,
        sending_header_key: match ratchet.state.sending_header_key {
            Some(key) => key.to_vec(),
            None => Vec::new(),
        },
        receiving_header_key: match ratchet.state.receiving_header_key {
            Some(key) => key.to_vec(),
            None => Vec::new(),
        },
        next_sending_header_key: ratchet.state.next_sending_header_key.to_vec(),
        next_receiving_header_key: match ratchet.state.next_receiving_header_key {
            Some(key) => key.to_vec(),
            None => Vec::new(),
        },
    };

    let mut skipped_keys = Vec::new();
    for ((header_key, message_number), message_key) in &ratchet.skipped_message_keys {
        skipped_keys.push(SkippedMessageKeyProto {
            header_key: header_key.to_vec(),
            message_number: *message_number,
            message_key: message_key.to_vec(),
        });
    }

    Ok(RatchetProto {
        dh_pair: dh_pair_bytes,
        state: Some(state_proto),
        skipped_message_keys: skipped_keys,
        max_skip: ratchet.max_skip,
    })
}

fn deserialize_ratchet(proto: RatchetProto) -> Result<DoubleRatchet, Error> {
    if proto.dh_pair.len() != 32 {
        return Err(Error::Serde("Invalid DH key pair length".to_string()));
    }

    let mut dh_pair_bytes = [0u8; 32];
    dh_pair_bytes.copy_from_slice(&proto.dh_pair);
    let dh_pair = StaticSecret::from(dh_pair_bytes);

    let state_proto = proto
        .state
        .ok_or_else(|| Error::Serde("Missing ratchet state".to_string()))?;

    let dh_remote_public = if !state_proto.dh_remote_public.is_empty() {
        if state_proto.dh_remote_public.len() != 32 {
            return Err(Error::Serde("Invalid remote public key length".to_string()));
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&state_proto.dh_remote_public);
        Some(PublicKey::from(pk_bytes))
    } else {
        None
    };

    if state_proto.root_key.len() != 32 {
        return Err(Error::Serde("Invalid root key length".to_string()));
    }
    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(&state_proto.root_key);

    let sending_chain_proto = state_proto
        .sending_chain
        .ok_or_else(|| Error::Serde("Missing sending chain".to_string()))?;
    let receiving_chain_proto = state_proto
        .receiving_chain
        .ok_or_else(|| Error::Serde("Missing receiving chain".to_string()))?;

    if sending_chain_proto.chain_key.len() != 32 || receiving_chain_proto.chain_key.len() != 32 {
        return Err(Error::Serde("Invalid chain key length".to_string()));
    }

    let mut sending_chain_key = [0u8; 32];
    let mut receiving_chain_key = [0u8; 32];
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
        let mut key = [0u8; 32];
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
        let mut key = [0u8; 32];
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
    let mut next_sending_header_key = [0u8; 32];
    next_sending_header_key.copy_from_slice(&state_proto.next_sending_header_key);

    let next_receiving_header_key = if !state_proto.next_receiving_header_key.is_empty() {
        if state_proto.next_receiving_header_key.len() != 32 {
            return Err(Error::Serde(
                "Invalid next receiving header key length".to_string(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&state_proto.next_receiving_header_key);
        Some(key)
    } else {
        None
    };

    let state = RatchetState {
        dh_pair,
        dh_remote_public,
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
        let mut header_key = [0u8; 32];
        header_key.copy_from_slice(&key.header_key);

        let mut message_key = [0u8; 32];
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
    use crate::{
        Account, AccountConfig, DoubleRatchet, IdentityKey, OneTimePreKey, PreKeyBundle, Session,
        SignedPreKey, X3DH,
    };
    use std::time::Duration;

    fn create_test_session_pair() -> (Session, Session) {
        // Set up identities and pre-keys
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);

        // Create Bob's pre-key bundle
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Alice performs X3DH with Bob's bundle
        let x3dh = X3DH::new(b"Test-Session-Protocol");
        let alice_x3dh_result = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();
        let alice_ephemeral_public = alice_x3dh_result.get_public_key();

        // Alice initializes her Double Ratchet
        let alice_ratchet = DoubleRatchet::initialize_as_first_sender(
            alice_x3dh_result.get_shared_secret(),
            &bob_bundle.get_signed_pre_key_public(),
        );

        // Create a session ID for Alice
        let alice_session_id = format!("alice-to-bob-{}", rand::random::<u32>());
        let alice_session = Session::new(alice_session_id, alice_ratchet, true);

        // Bob processes Alice's initiation
        let bob_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_ephemeral_public,
            )
            .unwrap();

        // Bob initializes his Double Ratchet
        let bob_ratchet = DoubleRatchet::initialize_as_first_receiver(
            bob_shared_secret,
            bob_signed_pre_key.get_key_pair(),
        );

        // Create a session ID for Bob
        let bob_session_id = format!("bob-to-alice-{}", rand::random::<u32>());
        let bob_session = Session::new(bob_session_id, bob_ratchet, false);

        (alice_session, bob_session)
    }

    #[test]
    fn test_account_serialization() {
        let config = AccountConfig {
            max_skipped_messages: 42,
            signed_pre_key_rotation_interval: Duration::from_secs(24 * 60 * 60 * 3), // 3 days
            min_one_time_pre_keys: 15,
            max_one_time_pre_keys: 75,
            protocol_info: b"Test-Protocol".to_vec(),
            kdf_info: b"Test-KDF".to_vec(),
        };
        let mut account = Account::new(Some(config));

        // Create a session for the account
        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_bundle = PreKeyBundle::new(&bob_identity, &bob_signed_pre_key, None);

        let session_id = account.initiate_session(&bob_bundle).unwrap();

        let serialized = account.serialize().unwrap();

        let deserialized_account = Account::deserialize(&serialized).unwrap();

        assert_eq!(
            account.ik.get_public_dh_key().as_bytes(),
            deserialized_account.ik.get_public_dh_key().as_bytes(),
            "Identity keys should match"
        );

        assert_eq!(
            account.spk.get_public_key().as_bytes(),
            deserialized_account.spk.get_public_key().as_bytes(),
            "Signed pre-keys should match"
        );

        assert_eq!(
            account.config.max_skipped_messages, deserialized_account.config.max_skipped_messages,
            "Config max_skipped_messages should match"
        );

        assert_eq!(
            account.config.signed_pre_key_rotation_interval,
            deserialized_account.config.signed_pre_key_rotation_interval,
            "Config rotation interval should match"
        );

        assert_eq!(
            account.config.protocol_info, deserialized_account.config.protocol_info,
            "Protocol info should match"
        );

        assert_eq!(
            account.otpk_store.count(),
            deserialized_account.otpk_store.count(),
            "One-time pre-key count should match"
        );

        assert!(
            deserialized_account.get_session(&session_id).is_some(),
            "Session should exist in deserialized account"
        );
    }

    #[test]
    fn test_session_full_functionality() {
        let (mut alice_session, mut bob_session) = create_test_session_pair();

        let message1 = "Hello Bob, this is a secure message!";
        let ad1 = b"context-1";
        let encrypted1 = alice_session.encrypt(message1.as_bytes(), ad1).unwrap();
        let decrypted1 = bob_session.decrypt(&encrypted1, ad1).unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), message1);

        let message2 = "Hello Alice, I received your message!";
        let ad2 = b"context-2";
        let encrypted2 = bob_session.encrypt(message2.as_bytes(), ad2).unwrap();
        let decrypted2 = alice_session.decrypt(&encrypted2, ad2).unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), message2);

        let alice_serialized = alice_session.serialize().unwrap();
        let bob_serialized = bob_session.serialize().unwrap();

        let mut alice_deserialized = Session::deserialize(alice_serialized).unwrap();
        let mut bob_deserialized = Session::deserialize(bob_serialized).unwrap();

        // Verify we can continue the conversation with deserialized sessions
        let message3 = "This message is sent after serialization!";
        let ad3 = b"context-3";
        let encrypted3 = alice_deserialized
            .encrypt(message3.as_bytes(), ad3)
            .unwrap();
        let decrypted3 = bob_deserialized.decrypt(&encrypted3, ad3).unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), message3);

        let message4 = "And this response is also after serialization!";
        let ad4 = b"context-4";
        let encrypted4 = bob_deserialized.encrypt(message4.as_bytes(), ad4).unwrap();
        let decrypted4 = alice_deserialized.decrypt(&encrypted4, ad4).unwrap();
        assert_eq!(String::from_utf8(decrypted4).unwrap(), message4);
    }

    #[test]
    fn test_out_of_order_messages_after_serialization() {
        let (mut alice_session, mut bob_session) = create_test_session_pair();

        // Alice sends multiple messages
        let messages = vec![
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
            "Message 5",
        ];

        let ad = b"out-of-order-test";
        let mut encrypted_messages = Vec::new();

        for msg in &messages {
            encrypted_messages.push(alice_session.encrypt(msg.as_bytes(), ad).unwrap());
        }

        // Bob receives first message normally
        let decrypted1 = bob_session.decrypt(&encrypted_messages[0], ad).unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), messages[0]);

        // Serialize Bob's session
        let bob_serialized = bob_session.serialize().unwrap();

        // Deserialize to a new session
        let mut bob_deserialized = Session::deserialize(bob_serialized).unwrap();

        // Receive messages out of order in the deserialized session
        let decrypted3 = bob_deserialized
            .decrypt(&encrypted_messages[2], ad)
            .unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), messages[2]);

        let decrypted2 = bob_deserialized
            .decrypt(&encrypted_messages[1], ad)
            .unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), messages[1]);

        let decrypted5 = bob_deserialized
            .decrypt(&encrypted_messages[4], ad)
            .unwrap();
        assert_eq!(String::from_utf8(decrypted5).unwrap(), messages[4]);

        let decrypted4 = bob_deserialized
            .decrypt(&encrypted_messages[3], ad)
            .unwrap();
        assert_eq!(String::from_utf8(decrypted4).unwrap(), messages[3]);
    }

    #[test]
    fn test_skipped_message_keys_serialization() {
        let (mut alice_session, mut bob_session) = create_test_session_pair();

        // Alice sends multiple messages
        let messages = vec![
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
            "Message 5",
        ];

        let ad = b"skipped-keys-test";
        let mut encrypted_messages = Vec::new();

        for msg in &messages {
            encrypted_messages.push(alice_session.encrypt(msg.as_bytes(), ad).unwrap());
        }

        // Bob receives first message
        let decrypted1 = bob_session.decrypt(&encrypted_messages[0], ad).unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), messages[0]);

        // Serialize Bob's session after receiving first message
        let bob_serialized = bob_session.serialize().unwrap();

        // Deserialize to a new session
        let mut bob_deserialized = Session::deserialize(bob_serialized).unwrap();

        // Skip to message 4, which should store messages 2 and 3 in skipped keys
        let decrypted4 = bob_deserialized
            .decrypt(&encrypted_messages[3], ad)
            .unwrap();
        assert_eq!(String::from_utf8(decrypted4).unwrap(), messages[3]);

        // Now go back and decrypt message 2, which should use skipped keys
        let decrypted2 = bob_deserialized
            .decrypt(&encrypted_messages[1], ad)
            .unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), messages[1]);

        // And message 3
        let decrypted3 = bob_deserialized
            .decrypt(&encrypted_messages[2], ad)
            .unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), messages[2]);
    }

    #[test]
    fn test_dh_ratchet_after_serialization() {
        let (mut alice_session, mut bob_session) = create_test_session_pair();

        // Exchange a few messages to advance the ratchet
        let messages = vec![
            "Alice message 1",
            "Bob response 1",
            "Alice message 2",
            "Bob response 2",
        ];

        let ad = b"ratchet-test";

        // First message from Alice to Bob
        let encrypted1 = alice_session.encrypt(messages[0].as_bytes(), ad).unwrap();
        let decrypted1 = bob_session.decrypt(&encrypted1, ad).unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), messages[0]);

        // Response from Bob to Alice
        let encrypted2 = bob_session.encrypt(messages[1].as_bytes(), ad).unwrap();
        let decrypted2 = alice_session.decrypt(&encrypted2, ad).unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), messages[1]);

        // Serialize both sessions
        let alice_serialized = alice_session.serialize().unwrap();
        let bob_serialized = bob_session.serialize().unwrap();

        // Deserialize
        let mut alice_deserialized = Session::deserialize(alice_serialized).unwrap();
        let mut bob_deserialized = Session::deserialize(bob_serialized).unwrap();

        // Continue conversation after deserialization
        let encrypted3 = alice_deserialized
            .encrypt(messages[2].as_bytes(), ad)
            .unwrap();
        let decrypted3 = bob_deserialized.decrypt(&encrypted3, ad).unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), messages[2]);

        let encrypted4 = bob_deserialized
            .encrypt(messages[3].as_bytes(), ad)
            .unwrap();
        let decrypted4 = alice_deserialized.decrypt(&encrypted4, ad).unwrap();
        assert_eq!(String::from_utf8(decrypted4).unwrap(), messages[3]);
    }
}

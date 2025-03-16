use crate::chain::Chain;
use crate::error::Error;
use crate::ratchet_message::{MessageHeader, RatchetMessage};
use crate::state::RatchetState;
use crate::{X25519PublicKey, X25519Secret, generate_random_seed};
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::HashMap;
use x25519_dalek::SharedSecret;
use zeroize::Zeroize;

const NONCE_SIZE: usize = 12; // AES-GCM uses 12-byte (96-bit) nonces

thread_local! {
    static AD_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(256));
}

fn with_ad_buffer<F, R>(f: F) -> R
where
    F: FnOnce(&mut Vec<u8>) -> R,
{
    AD_BUFFER.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        buffer.clear();
        f(&mut buffer)
    })
}

/// Double Ratchet implementation for the Signal Protocol.
///
/// The Double Ratchet algorithm provides forward secrecy (compromise of current keys
/// does not compromise past messages) and break-in recovery (compromise of current
/// keys does not compromise future messages as long as a DH ratchet step happens).
///
/// It manages:
/// - A root key that evolves with each DH ratchet step
/// - Separate sending and receiving chain keys for message encryption
/// - Header encryption keys for authentication
/// - Skipped message keys for out-of-order message delivery
#[derive(Clone)]
pub struct DoubleRatchet {
    pub(crate) state: RatchetState,
    // Map<(header_key, message_no): message_key>
    pub(crate) skipped_message_keys: HashMap<([u8; 32], u32), [u8; 32]>,
    pub(crate) max_skip: u32,
}

impl Default for DoubleRatchet {
    fn default() -> Self {
        todo!()
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        for (_, key) in self.skipped_message_keys.drain() {
            let mut key_copy = key;
            key_copy.zeroize();
        }
    }
}

impl DoubleRatchet {
    /// Get the current dh ratchet public key
    pub fn public_key(&self) -> X25519PublicKey {
        self.state.dh_pair.public_key()
    }

    /// Initializes a ratchet for the initiator (Alice).
    ///
    /// This is typically called by Alice after the X3DH key agreement,
    /// using the shared secret from X3DH and Bob's signed pre-key.
    pub fn initialize_for_alice(
        mut shared_secret: [u8; 32],
        receiver_public_key: &X25519PublicKey,
    ) -> Self {
        let dh_pair = X25519Secret::from(generate_random_seed().unwrap());

        // Perform initial DH and KDF
        let dh_output = dh_pair.dh(receiver_public_key);
        let (new_root_key, chain_key, next_sending_header_key) =
            Self::kdf_rk_he(&shared_secret, dh_output);

        let (header_key_a, next_header_key_b) =
            DoubleRatchet::derive_initial_header_keys(shared_secret);

        // Securely erase the shared secret
        shared_secret.zeroize();

        // Initialize chains
        let sending_chain = Chain::new(chain_key);

        Self {
            state: RatchetState {
                dh_pair,
                root_key: new_root_key,
                dh_remote_public: Some(*receiver_public_key),
                sending_chain,
                sending_header_key: Some(header_key_a),
                next_sending_header_key,
                next_receiving_header_key: Some(next_header_key_b),
                receiving_chain: Default::default(),
                previous_sending_chain_length: 0,
                sending_message_number: 0,
                receiving_message_number: 0,
                receiving_header_key: None,
            },
            skipped_message_keys: HashMap::with_capacity(100),
            max_skip: 100,
        }
    }

    /// Initializes a ratchet for the responder (Bob).
    ///
    /// This is typically called by Bob after processing
    /// the X3DH key agreement initiated by Alice.
    pub fn initialize_for_bob(shared_secret: [u8; 32], dh_pair: X25519Secret) -> Self {
        let (header_key_a, next_header_key_b) =
            DoubleRatchet::derive_initial_header_keys(shared_secret);

        Self {
            state: RatchetState {
                dh_pair,
                root_key: shared_secret,
                receiving_header_key: Some(header_key_a),
                next_sending_header_key: next_header_key_b,
                next_receiving_header_key: Some(header_key_a),
                dh_remote_public: None,
                sending_chain: Default::default(),
                sending_header_key: None,
                receiving_chain: Default::default(),
                previous_sending_chain_length: 0,
                sending_message_number: 0,
                receiving_message_number: 0,
            },
            skipped_message_keys: HashMap::with_capacity(100),
            max_skip: 100,
        }
    }

    fn derive_initial_header_keys(shared_secret: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);

        let mut header_key_a = [0u8; 32];
        let mut next_header_key_b = [0u8; 32];

        hkdf.expand(b"Zealot-Header-Key-A", &mut header_key_a)
            .expect("HKDF expansion failed");
        hkdf.expand(b"Zealot-Next-Header-Key-B", &mut next_header_key_b)
            .expect("HKDF expansion failed");

        (header_key_a, next_header_key_b)
    }

    /// Key derivation function for the root key ratchet with header encyption.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The new root key
    /// 2. The new chain key
    /// 3. The next header encryption key
    fn kdf_rk_he(
        root_key: &[u8; 32],
        mut dh_output: SharedSecret,
    ) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), &dh_output.to_bytes());

        let mut new_root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];
        let mut next_header_key = [0u8; 32];

        hkdf.expand(b"Zealot-E2E-Root", &mut new_root_key)
            .expect("HKDF expansion failed for root key");

        hkdf.expand(b"Zealot-E2E-Chain", &mut chain_key)
            .expect("HKDF expansion failed for chain key");

        hkdf.expand(b"Zealot-E2E-Next-Header", &mut next_header_key)
            .expect("HKDF expansion failed for next header key");

        dh_output.zeroize();

        (new_root_key, chain_key, next_header_key)
    }

    /// Encrypts a message using the Double Ratchet algorithm.
    ///
    /// This performs the following steps:
    /// 1. Generates a message key from the sending chain
    /// 2. Encrypts the message header with the header key
    /// 3. Encrypts the message with the message key
    /// 4. Increments the sending chain message counter
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RatchetMessage, Error> {
        let header = MessageHeader {
            public_key: self.public_key(),
            previous_chain_length: self.state.previous_sending_chain_length,
            message_number: self.state.sending_message_number,
        };
        let encrypted_header = self.encrypt_header(&header)?;

        let message_key = self.state.sending_chain.next();
        let ciphertext = with_ad_buffer(|buffer| {
            buffer.extend_from_slice(associated_data);
            buffer.extend_from_slice(&encrypted_header);
            Self::encrypt_message(&message_key, plaintext, buffer)
        })?;

        self.state.sending_message_number += 1;

        Ok(RatchetMessage {
            header: encrypted_header,
            ciphertext,
        })
    }

    /// Encrypts a message header.
    fn encrypt_header(&self, header: &MessageHeader) -> Result<Vec<u8>, Error> {
        if let Some(hk) = self.state.sending_header_key {
            let header_bytes = header.to_bytes();

            let mut nonce = [0u8; 12];
            rand::rng()
                .try_fill_bytes(&mut nonce)
                .map_err(|_| Error::Random)?;

            let key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&hk);
            let cipher = Aes256GcmSiv::new(key);
            let nonce = Nonce::from_slice(&nonce);

            let mut ciphertext = cipher
                .encrypt(nonce, header_bytes.as_ref())
                .map_err(|_| Error::Crypto("Header encryption failed".to_string()))?;

            let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
            result.extend_from_slice(nonce);
            result.append(&mut ciphertext);

            Ok(result)
        } else {
            Err(Error::Protocol(
                "No sending header key available".to_string(),
            ))
        }
    }

    /// Decrypts a message using the Double Ratchet algorithm.
    ///
    /// This performs the following steps:
    /// 1. Tries to decrypt with skipped message keys first
    /// 2. Decrypts the message header
    /// 3. Performs a DH ratchet step if needed
    /// 4. Generates any skipped message keys
    /// 5. Derives the message key and decrypts the message
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Try to decrypt with skipped message keys
        if let Some(plaintext) = self.try_skipped_message_keys(message, associated_data)? {
            return Ok(plaintext);
        }

        // Clone the state so that if the decryption fails, we revert back to the old state
        let old_state = self.state.clone();

        let header = self.try_decrypt_header(&message.header).map_err(|err| {
            self.state = old_state.clone();
            err
        })?;

        // Check if ratchet public key has changed
        if self.state.dh_remote_public.is_none()
            || header.public_key != self.state.dh_remote_public.unwrap()
        {
            // Ratchet step - DH key has changed
            self.dh_ratchet(&header).map_err(|err| {
                self.state = old_state.clone();
                err
            })?;
        }

        // Skip ahead if needed
        if header.message_number > self.state.receiving_message_number {
            self.skip_message_keys(header.message_number)
                .map_err(|err| {
                    self.state = old_state.clone();
                    err
                })?;
        }

        // Get the current message key
        let message_key = self.state.receiving_chain.next();

        let plaintext = with_ad_buffer(|buffer| {
            buffer.extend_from_slice(associated_data);
            buffer.extend_from_slice(&message.header);
            Self::decrypt_message(&message_key, &message.ciphertext, buffer)
        })
        .map_err(|err| {
            self.state = old_state.clone();
            err
        })?;

        self.state.receiving_message_number += 1;

        Ok(plaintext)
    }

    /// Decrypts a message header using a specific header key.
    fn decrypt_header(&self, encrypted_header: &[u8], hk: &[u8; 32]) -> Option<MessageHeader> {
        if encrypted_header.len() < 12 {
            return None;
        }

        let nonce = &encrypted_header[0..12];
        let ciphertext = &encrypted_header[12..];

        let key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(hk);
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(nonce);

        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => {
                if plaintext.len() != 40 {
                    return None;
                }

                let mut header_bytes = [0u8; 40];
                header_bytes.copy_from_slice(&plaintext);
                Some(MessageHeader::from(header_bytes))
            }
            Err(_) => None,
        }
    }

    /// Tries to decrypt a header with both current and next header keys.
    ///
    /// This allows for recovery if a header key rotation has happened.
    fn try_decrypt_header(&mut self, encrypted_header: &[u8]) -> Result<MessageHeader, Error> {
        if let Some(rhk) = self.state.receiving_header_key {
            if let Some(header) = self.decrypt_header(encrypted_header, &rhk) {
                return Ok(header);
            }
        }

        if let Some(nrhk) = self.state.next_receiving_header_key {
            if let Some(header) = self.decrypt_header(encrypted_header, &nrhk) {
                return Ok(header);
            }
        }

        Err(Error::Protocol("Failed to decrypt header".to_string()))
    }

    /// Tries to decrypt a message using previously skipped message keys.
    ///
    /// This is used for handling out-of-order messages.
    fn try_skipped_message_keys(
        &mut self,
        message: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        for ((header_key, message_no), message_key) in &self.skipped_message_keys {
            if let Some(header) = self.decrypt_header(&message.header, header_key) {
                if header.message_number != *message_no {
                    continue;
                }

                let plaintext = with_ad_buffer(|buffer| {
                    buffer.extend_from_slice(associated_data);
                    buffer.extend_from_slice(&message.header);
                    Self::decrypt_message(message_key, &message.ciphertext, buffer)
                })?;

                self.skipped_message_keys
                    .remove(&(*header_key, *message_no));

                return Ok(Some(plaintext));
            }
        }

        Ok(None)
    }

    /// Performs a Diffie-Hellman ratchet step.
    fn dh_ratchet(&mut self, header: &MessageHeader) -> Result<(), Error> {
        self.state.previous_sending_chain_length = self.state.sending_chain.get_index();

        // Update remote public key
        self.state.dh_remote_public = Some(header.public_key);

        // Reset message counters
        self.state.receiving_message_number = 0;
        self.state.sending_message_number = 0;

        self.state.receiving_header_key = self.state.next_receiving_header_key;
        self.state.sending_header_key = Some(self.state.next_sending_header_key);

        // Derive new receiving chain
        let dh_output = self.state.dh_pair.dh(&header.public_key);
        let (new_root_key, chain_key, next_header_key) =
            Self::kdf_rk_he(&self.state.root_key, dh_output);
        self.state.root_key = new_root_key;
        self.state.receiving_chain = Chain::new(chain_key);
        self.state.next_receiving_header_key = Some(next_header_key);

        // Generate new DH key pair
        self.state.dh_pair = X25519Secret::from(generate_random_seed()?);

        // Derive new sending chain
        let dh_output = self.state.dh_pair.dh(&header.public_key);
        let (new_root_key, chain_key, next_header_key) =
            Self::kdf_rk_he(&self.state.root_key, dh_output);
        self.state.root_key = new_root_key;
        self.state.sending_chain = Chain::new(chain_key);
        self.state.next_sending_header_key = next_header_key;

        Ok(())
    }

    /// Generates and stores skipped message keys.
    ///
    /// When receiving a message with a higher message number than expected,
    /// this method generates all the intermediate message keys to maintain
    /// security and allow for later decryption of out-of-order messages.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), Error> {
        if self.state.receiving_message_number + self.max_skip < until {
            return Err(Error::Protocol("Too many skipped messages".to_string()));
        }

        if self.state.receiving_chain.chain_key != [0u8; 32] {
            while self.state.receiving_message_number < until {
                let message_key = self.state.receiving_chain.next();

                if let Some(rhk) = self.state.receiving_header_key {
                    self.skipped_message_keys
                        .insert((rhk, self.state.receiving_message_number), message_key);
                }

                self.state.receiving_message_number += 1;
            }
        }

        Ok(())
    }

    /// Encrypt a message
    fn encrypt_message(
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Derive encryption key, authentication key, and IV from the message key
        let hkdf = Hkdf::<Sha256>::new(None, key);

        // Generate 80 bytes: 32 for encryption key, 32 for auth key, 16 for IV
        let mut derived_material = [0u8; 80];
        hkdf.expand(b"Zealot-E2E-Keys", &mut derived_material)
            .expect("HKDF expansion failed");

        // Extract the nonce (use first 12 bytes of the IV)
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&derived_material[64..64 + NONCE_SIZE]);

        // Use the encryption key for AES-GCM
        let key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&derived_material[0..32]);
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .encrypt(
                nonce,
                aes_gcm_siv::aead::Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| Error::Protocol("Message encryption failed".to_string()))
    }

    /// Decrypt a message
    fn decrypt_message(
        key: &[u8; 32],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let hkdf = Hkdf::<Sha256>::new(None, key);

        let mut derived_material = [0u8; 80];
        hkdf.expand(b"Zealot-E2E-Keys", &mut derived_material)
            .expect("HKDF expansion failed");

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&derived_material[64..64 + NONCE_SIZE]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let aes_key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&derived_material[0..32]);
        let cipher = Aes256GcmSiv::new(aes_key);

        cipher
            .decrypt(
                nonce,
                aes_gcm_siv::aead::Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| Error::Protocol("Message decryption failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey, X3DH};
    use rand::TryRngCore;
    use rand::rngs::OsRng;

    fn create_ratchets() -> (DoubleRatchet, DoubleRatchet) {
        let bob_spk = SignedPreKey::new(1);

        // For simplicity, let's create a dummy shared secret
        let mut shared_secret = [0u8; 32];
        OsRng.try_fill_bytes(&mut shared_secret).unwrap();

        // Initialize ratchets
        let alice_ratchet =
            DoubleRatchet::initialize_for_alice(shared_secret, &bob_spk.public_key());

        let bob_ratchet = DoubleRatchet::initialize_for_bob(shared_secret, bob_spk.key_pair());

        (alice_ratchet, bob_ratchet)
    }

    #[test]
    fn test_basic_communication() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Send a message from Alice to Bob
        let alice_message = "Hello, Bob!";
        let encrypted_message = alice_ratchet
            .encrypt(alice_message.as_bytes(), b"AD")
            .unwrap();

        // Bob decrypts Alice's message
        let decrypted = bob_ratchet.decrypt(&encrypted_message, b"AD").unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), alice_message);

        // Bob responds to Alice
        let bob_message = "Hello, Alice!";
        let encrypted_response = bob_ratchet.encrypt(bob_message.as_bytes(), b"AD").unwrap();

        // Alice decrypts Bob's response
        let decrypted_response = alice_ratchet.decrypt(&encrypted_response, b"AD").unwrap();
        assert_eq!(String::from_utf8(decrypted_response).unwrap(), bob_message);
    }

    #[test]
    fn test_multiple_messages() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Send multiple messages from Alice to Bob
        let messages = vec![
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
            "Message 5",
        ];

        for msg in &messages {
            let encrypted = alice_ratchet.encrypt(msg.as_bytes(), b"AD").unwrap();
            let decrypted = bob_ratchet.decrypt(&encrypted, b"AD").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), *msg);
        }

        // Send multiple messages from Bob to Alice
        let responses = vec!["Response 1", "Response 2", "Response 3"];

        for msg in &responses {
            let encrypted = bob_ratchet.encrypt(msg.as_bytes(), b"AD").unwrap();
            let decrypted = alice_ratchet.decrypt(&encrypted, b"AD").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), *msg);
        }
    }

    #[test]
    fn test_out_of_order_messages() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Alice sends multiple messages
        let messages = vec![
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
            "Message 5",
        ];
        let mut encrypted_messages = Vec::new();

        for msg in &messages {
            encrypted_messages.push(alice_ratchet.encrypt(msg.as_bytes(), b"AD").unwrap());
        }

        // Bob receives them out of order: 0, 2, 1, 4, 3
        let decrypted1 = bob_ratchet
            .decrypt(&encrypted_messages[0].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), messages[0]);

        let decrypted3 = bob_ratchet
            .decrypt(&encrypted_messages[2].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), messages[2]);

        let decrypted5 = bob_ratchet
            .decrypt(&encrypted_messages[4].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted5).unwrap(), messages[4]);

        let decrypted2 = bob_ratchet
            .decrypt(&encrypted_messages[1].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), messages[1]);

        let decrypted4 = bob_ratchet
            .decrypt(&encrypted_messages[3].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted4).unwrap(), messages[3]);
    }

    #[test]
    fn test_key_rotation() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Initial message exchange to establish the ratchet
        let alice_message = "Hello, Bob!";
        let encrypted_message = alice_ratchet
            .encrypt(alice_message.as_bytes(), b"AD")
            .unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted_message, b"AD").unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), alice_message);

        // Save current ratchet state for later comparison
        let alice_initial_public = alice_ratchet.public_key();

        // Send multiple messages back and forth to trigger key rotation
        for i in 0..5 {
            // Bob to Alice
            let bob_msg = format!("Message from Bob {}", i);
            let encrypted = bob_ratchet.encrypt(bob_msg.as_bytes(), b"AD").unwrap();
            let decrypted = alice_ratchet.decrypt(&encrypted, b"AD").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), bob_msg);

            // Alice to Bob
            let alice_msg = format!("Message from Alice {}", i);
            let encrypted = alice_ratchet.encrypt(alice_msg.as_bytes(), b"AD").unwrap();
            let decrypted = bob_ratchet.decrypt(&encrypted, b"AD").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), alice_msg);
        }

        // Verify that Alice's public key has changed (indicating DH ratchet turned)
        let alice_final_public = alice_ratchet.public_key();
        assert_ne!(
            alice_initial_public.as_bytes(),
            alice_final_public.as_bytes(),
            "DH keys should have rotated during the conversation"
        );
    }

    #[test]
    fn test_with_x3dh() {
        // 1. Set up identities and prekeys
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);

        // 2. Create Bob's bundle
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // 3. Alice performs X3DH with Bob's bundle
        let x3dh = X3DH::new(b"Test-Signal-Protocol");
        let alice_x3dh_result = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();
        let alice_public_key = alice_x3dh_result.public_key();
        // 4. Alice initializes her Double Ratchet with the shared secret
        let mut alice_ratchet = DoubleRatchet::initialize_for_alice(
            alice_x3dh_result.shared_secret(),
            &bob_bundle.public_signed_pre_key(),
        );
        // 5. Bob processes Alice's initiation
        let bob_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.public_dh_key(),
                &alice_public_key,
            )
            .unwrap();
        // 6. Bob initializes his Double Ratchet with the shared secret
        let mut bob_ratchet =
            DoubleRatchet::initialize_for_bob(bob_shared_secret, bob_signed_pre_key.key_pair());
        // 7. Test message exchange
        let message = "This is a secure message using X3DH + Double Ratchet!";
        let encrypted = alice_ratchet.encrypt(message.as_bytes(), b"AD").unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted, b"AD").unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), message);

        // 8. Test reply
        let reply = "Received your message securely!";
        let encrypted_reply = bob_ratchet.encrypt(reply.as_bytes(), b"AD").unwrap();
        let decrypted_reply = alice_ratchet.decrypt(&encrypted_reply, b"AD").unwrap();

        assert_eq!(String::from_utf8(decrypted_reply).unwrap(), reply);
    }

    #[test]
    fn test_large_message() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Create a large message (100KB)
        let large_message = vec![b'A'; 100 * 1024];

        // Encrypt and decrypt
        let encrypted = alice_ratchet.encrypt(&large_message, b"AD").unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted, b"AD").unwrap();

        assert_eq!(decrypted, large_message);
    }

    #[test]
    fn test_empty_message() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        let empty_message = b"";
        let encrypted = alice_ratchet.encrypt(empty_message, b"AD").unwrap();
        let decrypted = bob_ratchet
            .decrypt(&encrypted, b"AD")
            .map_err(|err| {
                println!("{}", err.to_string());
                err
            })
            .unwrap();

        assert_eq!(decrypted, empty_message);
    }

    #[test]
    fn test_too_many_skipped_messages() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Set a very low max_skip value for testing
        bob_ratchet.max_skip = 2;

        // Alice sends multiple messages
        let mut encrypted_messages = Vec::new();
        for i in 0..5 {
            let msg = format!("Message {}", i);
            encrypted_messages.push(alice_ratchet.encrypt(msg.as_bytes(), b"AD").unwrap());
        }

        // Bob receives first message
        let _ = bob_ratchet
            .decrypt(&encrypted_messages[0].clone(), b"AD")
            .unwrap();

        // Bob tries to decrypt message 4 (skipping 3 messages, which exceeds max_skip=2)
        let result = bob_ratchet.decrypt(&encrypted_messages[4].clone(), b"AD");
        assert!(result.is_err());

        // But message 3 should work (skipping 2 messages)
        let result = bob_ratchet.decrypt(&encrypted_messages[3].clone(), b"AD");
        assert!(result.is_ok());
    }
}

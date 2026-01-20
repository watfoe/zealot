mod chain;
mod message;
mod state;

use crate::X3DHSharedSecret;
use crate::error::Error;
use crate::generate_random_seed;
pub(crate) use crate::ratchet::chain::Chain;
use crate::ratchet::message::MessageHeader;
pub use crate::ratchet::message::RatchetMessage;
pub(crate) use crate::ratchet::state::RatchetState;
use crate::{X25519PublicKey, X25519Secret};
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::HashMap;
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    pub(crate) skipped_message_keys: HashMap<(Box<[u8; 32]>, u32), Box<[u8; 32]>>,
    pub(crate) max_skip: u32,
}

impl Zeroize for DoubleRatchet {
    fn zeroize(&mut self) {
        self.state.zeroize();
        for ((mut hk, _), mut key) in self.skipped_message_keys.drain() {
            hk.zeroize();
            key.zeroize();
        }
    }
}

impl ZeroizeOnDrop for DoubleRatchet {}

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
        mut shared_secret: X3DHSharedSecret,
        bob_public_key: &X25519PublicKey,
        max_skipped_messages: u32,
        ad: Box<[u8; 64]>,
    ) -> Self {
        let seed = generate_random_seed();
        let dh_pair = X25519Secret::from(seed);

        // Perform initial DH and KDF
        let dh_output = dh_pair.dh(bob_public_key);
        let (new_root_key, chain_key, next_sending_header_key) =
            Self::kdf_rk_he(&shared_secret.0, dh_output);

        let (header_key_a, next_header_key_b) =
            DoubleRatchet::derive_initial_header_keys(&shared_secret.0);

        shared_secret.zeroize();

        // Initialize chains
        let sending_chain = Chain::new(chain_key);

        Self {
            state: RatchetState {
                ad,
                root_key: new_root_key,
                dh_pair,
                remote_dh_key_public: Some(*bob_public_key),
                sending_chain,
                sending_header_key: Some(header_key_a),
                next_sending_header_key,
                receiving_chain: Default::default(),
                receiving_header_key: None,
                next_receiving_header_key: Some(next_header_key_b),
                previous_sending_chain_length: 0,
                sending_message_number: 0,
                receiving_message_number: 0,
            },
            skipped_message_keys: HashMap::new(),
            max_skip: max_skipped_messages,
        }
    }

    /// Initializes a ratchet for the responder (Bob).
    ///
    /// This is typically called by Bob after processing
    /// the X3DH key agreement initiated by Alice.
    pub fn initialize_for_bob(
        shared_secret: X3DHSharedSecret,
        dh_pair: X25519Secret,
        max_skipped_messages: u32,
        ad: Box<[u8; 64]>,
    ) -> Self {
        let (header_key_a, next_header_key_b) =
            DoubleRatchet::derive_initial_header_keys(&shared_secret.0);

        Self {
            state: RatchetState {
                ad,
                root_key: shared_secret.0.clone(),
                dh_pair,
                remote_dh_key_public: None,
                sending_chain: Default::default(),
                sending_header_key: None,
                next_sending_header_key: next_header_key_b,
                receiving_chain: Default::default(),
                receiving_header_key: None,
                next_receiving_header_key: Some(header_key_a),
                previous_sending_chain_length: 0,
                sending_message_number: 0,
                receiving_message_number: 0,
            },
            skipped_message_keys: HashMap::new(),
            max_skip: max_skipped_messages,
        }
    }

    fn derive_initial_header_keys(root_key: &[u8; 32]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        let hkdf = Hkdf::<Sha256>::new(None, root_key);

        let mut header_key_a = Box::new([0u8; 32]);
        let mut next_header_key_b = Box::new([0u8; 32]);

        hkdf.expand(b"Zealot-Header-Key-A", header_key_a.as_mut_slice())
            .expect("HKDF expansion failed");
        hkdf.expand(
            b"Zealot-Next-Header-Key-B",
            next_header_key_b.as_mut_slice(),
        )
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
    ) -> (Box<[u8; 32]>, Box<[u8; 32]>, Box<[u8; 32]>) {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), &dh_output.to_bytes());

        let mut new_root_key = Box::new([0u8; 32]);
        let mut chain_key = Box::new([0u8; 32]);
        let mut next_header_key = Box::new([0u8; 32]);

        hkdf.expand(b"Zealot-E2E-Root", new_root_key.as_mut_slice())
            .expect("HKDF expansion failed for root key");

        hkdf.expand(b"Zealot-E2E-Chain", chain_key.as_mut_slice())
            .expect("HKDF expansion failed for chain key");

        hkdf.expand(b"Zealot-E2E-Next-Header", next_header_key.as_mut_slice())
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
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, Error> {
        let header = MessageHeader {
            public_key: self.public_key(),
            previous_chain_length: self.state.previous_sending_chain_length,
            message_number: self.state.sending_message_number,
        };
        let encrypted_header = self.encrypt_header(&header)?;

        let message_key = self.state.sending_chain.next();
        let ciphertext = with_ad_buffer(|buffer| {
            buffer.extend_from_slice(self.state.ad.as_slice());
            buffer.extend_from_slice(&encrypted_header);
            Self::encrypt_message(&message_key, plaintext, buffer)
        })?;

        self.state.sending_message_number = self.state.sending_message_number.wrapping_add(1);

        Ok(RatchetMessage {
            header: encrypted_header,
            ciphertext,
        })
    }

    /// Encrypts a message header.
    fn encrypt_header(&self, header: &MessageHeader) -> Result<Vec<u8>, Error> {
        if let Some(ref hk) = self.state.sending_header_key {
            let header_bytes = header.to_bytes();

            let mut nonce_slice = Box::new([0u8; 12]);
            rand::rng()
                .try_fill_bytes(nonce_slice.as_mut_slice())
                .map_err(|_| Error::Random)?;

            let key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(hk.as_slice());
            let cipher = Aes256GcmSiv::new(key);
            let nonce = Nonce::from_slice(nonce_slice.as_slice());

            let mut ciphertext = cipher
                .encrypt(nonce, header_bytes.as_ref())
                .map_err(|_| Error::Crypto("Header encryption failed".to_string()))?;

            let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
            result.extend_from_slice(nonce);
            result.append(&mut ciphertext);

            nonce_slice.zeroize();

            Ok(result)
        } else {
            Err(Error::Protocol(
                "No sending header key available".to_string(),
            ))
        }
    }

    /// Encrypt a message
    fn encrypt_message(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        // Derive encryption key and IV from the message key
        let hkdf = Hkdf::<Sha256>::new(None, key);

        let mut derived_material = [0u8; 44];
        hkdf.expand(b"Zealot-E2E-Keys", &mut derived_material)
            .expect("HKDF expansion failed");

        let key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&derived_material[0..32]);
        let cipher = Aes256GcmSiv::new(key);

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&derived_material[32..44]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .encrypt(
                nonce,
                aes_gcm_siv::aead::Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| Error::Protocol("Message encryption failed".to_string()))
    }

    /// Decrypts a message using the Double Ratchet algorithm.
    ///
    /// This performs the following steps:
    /// 1. Tries to decrypt with skipped message keys first
    /// 2. Decrypts the message header
    /// 3. Performs a DH ratchet step if needed
    /// 4. Generates any skipped message keys
    /// 5. Derives the message key and decrypts the message
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>, Error> {
        // Clone the state so that if the decryption fails, we revert back to the old state
        let old_state = self.state.clone();

        match self.try_skipped_message_keys(message) {
            Ok(plaintext) => {
                if let Some(plaintext) = plaintext {
                    return Ok(plaintext);
                }
            }
            Err(err) => {
                self.state = old_state;
                return Err(err);
            }
        }

        let (header, should_ratchet) = self.try_decrypt_header(&message.header)?;

        if should_ratchet {
            self.skip_message_keys(header.previous_chain_length)?;
            // Ratchet step - Rotate the keys
            self.dh_ratchet(&header);
        }

        // Skip ahead if needed
        if header.message_number > self.state.receiving_message_number {
            if let Err(err) = self.skip_message_keys(header.message_number) {
                self.state = old_state;
                return Err(err);
            }
        }

        // Current message key
        let message_key = self.state.receiving_chain.next();
        self.state.receiving_message_number = self.state.receiving_message_number.wrapping_add(1);

        let plaintext = with_ad_buffer(|buffer| {
            buffer.extend_from_slice(self.state.ad.as_slice());
            buffer.extend_from_slice(&message.header);
            Self::decrypt_message(&message_key, &message.ciphertext, buffer)
        })
        .inspect_err(|_| {
            self.state = old_state;
        })?;

        Ok(plaintext)
    }

    /// Tries to decrypt a message using previously skipped message keys.
    ///
    /// This is used for handling out-of-order messages.
    fn try_skipped_message_keys(
        &mut self,
        message: &RatchetMessage,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut key = None;

        for (header_key, message_no) in self.skipped_message_keys.keys() {
            if let Some(header) = self.decrypt_header(&message.header, header_key) {
                if header.message_number == *message_no {
                    key = Some((header_key, *message_no));
                    break;
                }
            }
        }

        if let Some((header_key, message_no)) = key {
            let message_key = self
                .skipped_message_keys
                .remove(&(header_key.clone(), message_no))
                .expect("Key must exist");

            let plaintext = with_ad_buffer(|buffer| {
                buffer.extend_from_slice(self.state.ad.as_slice());
                buffer.extend_from_slice(&message.header);
                Self::decrypt_message(&message_key, &message.ciphertext, buffer)
            })?;

            return Ok(Some(plaintext));
        }

        Ok(None)
    }

    /// Tries to decrypt a header with both current and next header keys.
    ///
    /// This allows for recovery if a header key rotation has happened.
    fn try_decrypt_header(&self, encrypted_header: &[u8]) -> Result<(MessageHeader, bool), Error> {
        if let Some(ref rhk) = self.state.receiving_header_key {
            if let Some(header) = self.decrypt_header(encrypted_header, rhk) {
                return Ok((header, false));
            }
        }

        if let Some(ref nrhk) = self.state.next_receiving_header_key {
            if let Some(header) = self.decrypt_header(encrypted_header, nrhk) {
                return Ok((header, true));
            }
        }

        Err(Error::Protocol("Failed to decrypt header".to_string()))
    }

    /// Decrypts a message header using a specific header key.
    fn decrypt_header(&self, encrypted_header: &[u8], hk: &[u8; 32]) -> Option<MessageHeader> {
        if encrypted_header.len() < 12 {
            return None;
        }

        let nonce = &encrypted_header[0..12];
        let ciphertext = &encrypted_header[12..];

        let key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(hk.as_slice());
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

    /// Performs a Diffie-Hellman ratchet step.
    fn dh_ratchet(&mut self, header: &MessageHeader) {
        let seed = generate_random_seed();

        self.state.previous_sending_chain_length = self.state.sending_chain.index;

        // Update remote public key
        self.state.remote_dh_key_public = Some(header.public_key);

        // Reset message counters
        self.state.receiving_message_number = 0;
        self.state.sending_message_number = 0;

        self.state.receiving_header_key = self.state.next_receiving_header_key.clone();
        self.state.sending_header_key = Some(self.state.next_sending_header_key.clone());

        // Derive new receiving chain
        let dh_output = self.state.dh_pair.dh(&header.public_key);
        let (new_root_key, chain_key, next_header_key) =
            Self::kdf_rk_he(&self.state.root_key, dh_output);
        self.state.root_key = new_root_key;
        self.state.receiving_chain = Chain::new(chain_key);
        self.state.next_receiving_header_key = Some(next_header_key);

        // Generate new DH key pair
        self.state.dh_pair = X25519Secret::from(seed);

        // Derive new sending chain
        let dh_output = self.state.dh_pair.dh(&header.public_key);
        let (new_root_key, chain_key, next_header_key) =
            Self::kdf_rk_he(&self.state.root_key, dh_output);
        self.state.root_key = new_root_key;
        self.state.sending_chain = Chain::new(chain_key);
        self.state.next_sending_header_key = next_header_key;
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

        if self.state.receiving_chain.chain_key.as_ref() != &[0u8; 32] {
            while self.state.receiving_message_number < until {
                let message_key = self.state.receiving_chain.next();

                if let Some(rhk) = self.state.receiving_header_key.clone() {
                    self.skipped_message_keys
                        .insert((rhk, self.state.receiving_message_number), message_key);
                }

                self.state.receiving_message_number =
                    self.state.receiving_message_number.wrapping_add(1);
            }
        }

        Ok(())
    }

    /// Decrypt a message
    fn decrypt_message(key: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        let hkdf = Hkdf::<Sha256>::new(None, key.as_slice());

        let mut derived_material = [0u8; 44];
        hkdf.expand(b"Zealot-E2E-Keys", &mut derived_material)
            .expect("HKDF expansion failed");

        let aes_key = aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&derived_material[0..32]);
        let cipher = Aes256GcmSiv::new(aes_key);

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&derived_material[32..44]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(
                nonce,
                aes_gcm_siv::aead::Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| Error::Protocol("Message decryption failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignedPreKey;
    use rand::rand_core::OsRng;

    fn create_ratchets() -> (DoubleRatchet, DoubleRatchet) {
        let bob_spk = SignedPreKey::new(1);

        // For simplicity, let's create a dummy shared secret
        let shared_secret = generate_random_seed();

        let mut ad = Box::new([0u8; 64]);
        OsRng.try_fill_bytes(ad.as_mut_slice()).unwrap();

        // Initialize ratchets
        let alice_ratchet = DoubleRatchet::initialize_for_alice(
            X3DHSharedSecret(shared_secret.clone()),
            &bob_spk.public_key(),
            20,
            ad.clone(),
        );

        let bob_ratchet = DoubleRatchet::initialize_for_bob(
            X3DHSharedSecret(shared_secret),
            bob_spk.key_pair(),
            20,
            ad,
        );

        (alice_ratchet, bob_ratchet)
    }

    #[test]
    fn test_basic_communication() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Send a message from Alice to Bob
        let alice_message = "Hello, Bob!";
        let encrypted_message = alice_ratchet.encrypt(alice_message.as_bytes()).unwrap();

        // Bob decrypts Alice's message
        let decrypted = bob_ratchet.decrypt(&encrypted_message).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), alice_message);

        // Bob responds to Alice
        let bob_message = "Hello, Alice!";
        let encrypted_response = bob_ratchet.encrypt(bob_message.as_bytes()).unwrap();

        // Alice decrypts Bob's response
        let decrypted_response = alice_ratchet.decrypt(&encrypted_response).unwrap();
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
            let encrypted = alice_ratchet.encrypt(msg.as_bytes()).unwrap();
            let decrypted = bob_ratchet.decrypt(&encrypted).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), *msg);
        }

        // Send multiple messages from Bob to Alice
        let responses = vec!["Response 1", "Response 2", "Response 3"];

        for msg in &responses {
            let encrypted = bob_ratchet.encrypt(msg.as_bytes()).unwrap();
            let decrypted = alice_ratchet.decrypt(&encrypted).unwrap();
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
            encrypted_messages.push(alice_ratchet.encrypt(msg.as_bytes()).unwrap());
        }

        // Bob receives them out of order: 0, 2, 1, 4, 3
        let decrypted1 = bob_ratchet.decrypt(&encrypted_messages[0].clone()).unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), messages[0]);

        let decrypted3 = bob_ratchet.decrypt(&encrypted_messages[2].clone()).unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), messages[2]);

        let decrypted5 = bob_ratchet.decrypt(&encrypted_messages[4].clone()).unwrap();
        assert_eq!(String::from_utf8(decrypted5).unwrap(), messages[4]);

        let decrypted2 = bob_ratchet.decrypt(&encrypted_messages[1].clone()).unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), messages[1]);

        let decrypted4 = bob_ratchet.decrypt(&encrypted_messages[3].clone()).unwrap();
        assert_eq!(String::from_utf8(decrypted4).unwrap(), messages[3]);
    }

    #[test]
    fn test_key_rotation() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Initial message exchange to establish the ratchet
        let alice_message = "Hello, Bob!";
        let encrypted_message = alice_ratchet.encrypt(alice_message.as_bytes()).unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted_message).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), alice_message);

        // Save current ratchet state for later comparison
        let alice_initial_public = alice_ratchet.public_key();

        // Send multiple messages back and forth to trigger key rotation
        for i in 0..5 {
            // Bob to Alice
            let bob_msg = format!("Message from Bob {}", i);
            let encrypted = bob_ratchet.encrypt(bob_msg.as_bytes()).unwrap();
            let decrypted = alice_ratchet.decrypt(&encrypted).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), bob_msg);

            // Alice to Bob
            let alice_msg = format!("Message from Alice {}", i);
            let encrypted = alice_ratchet.encrypt(alice_msg.as_bytes()).unwrap();
            let decrypted = bob_ratchet.decrypt(&encrypted).unwrap();
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
    fn test_large_message() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Create a large message (100KB)
        let large_message = vec![b'A'; 100 * 1024];

        // Encrypt and decrypt
        let encrypted = alice_ratchet.encrypt(&large_message).unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, large_message);
    }

    #[test]
    fn test_empty_message() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        let empty_message = b"";
        let encrypted = alice_ratchet.encrypt(empty_message).unwrap();
        let decrypted = bob_ratchet
            .decrypt(&encrypted)
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
            encrypted_messages.push(alice_ratchet.encrypt(msg.as_bytes()).unwrap());
        }

        // Bob receives first message
        let _ = bob_ratchet.decrypt(&encrypted_messages[0].clone()).unwrap();

        // Bob tries to decrypt message 4 (skipping 3 messages, which exceeds max_skip=2)
        let result = bob_ratchet.decrypt(&encrypted_messages[4].clone());
        assert!(result.is_err());

        // But message 3 should work (skipping 2 messages)
        let result = bob_ratchet.decrypt(&encrypted_messages[3].clone());
        assert!(result.is_ok());
    }
}

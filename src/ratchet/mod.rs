mod chain;
mod message;
mod skipped;
mod state;

use crate::X3DHSharedSecret;
use crate::error::Error;
pub(crate) use crate::ratchet::chain::{Chain, MessageKey};
use crate::ratchet::message::MessageHeader;
pub use crate::ratchet::message::RatchetMessage;
use crate::ratchet::skipped::MAX_SKIPPED_MESSAGE_KEYS;
pub(crate) use crate::ratchet::skipped::SkippedKeys;
pub(crate) use crate::ratchet::state::RatchetState;
use crate::{X25519PublicKey, X25519Secret};
use crate::{generate_random_seed, try_generate_random_seed};
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::Sha256;
use std::cell::RefCell;
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Fills `okm` with HKDF-SHA256 output keying material for `info`.
#[expect(
    clippy::expect_used,
    reason = "HKDF-SHA256 only rejects outputs longer than 255 * 32 bytes and every caller asks for at most 44"
)]
fn hkdf_expand(hkdf: &Hkdf<Sha256>, info: &[u8], okm: &mut [u8]) {
    hkdf.expand(info, okm)
        .expect("HKDF output length is within bounds");
}

/// A new root key, a new chain key and the next header key, in that order.
type RootKdfOutput = (Box<[u8; 32]>, Box<[u8; 32]>, Box<[u8; 32]>);

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
    /// Keys for messages that were skipped over, bounded by
    /// [`MAX_SKIPPED_MESSAGE_KEYS`].
    pub(crate) skipped_message_keys: SkippedKeys,
    pub(crate) max_skip: u32,
}

impl Zeroize for DoubleRatchet {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.skipped_message_keys.clear();
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.zeroize();
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
            skipped_message_keys: SkippedKeys::default(),
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
            skipped_message_keys: SkippedKeys::default(),
            max_skip: max_skipped_messages,
        }
    }

    fn derive_initial_header_keys(root_key: &[u8; 32]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        let hkdf = Hkdf::<Sha256>::new(None, root_key);

        let mut header_key_a = Box::new([0u8; 32]);
        let mut next_header_key_b = Box::new([0u8; 32]);

        hkdf_expand(&hkdf, b"Zealot-Header-Key-A", header_key_a.as_mut_slice());
        hkdf_expand(
            &hkdf,
            b"Zealot-Next-Header-Key-B",
            next_header_key_b.as_mut_slice(),
        );

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
    fn kdf_rk_he(root_key: &[u8; 32], dh_output: SharedSecret) -> RootKdfOutput {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output.as_bytes());

        let mut new_root_key = Box::new([0u8; 32]);
        let mut chain_key = Box::new([0u8; 32]);
        let mut next_header_key = Box::new([0u8; 32]);

        hkdf_expand(&hkdf, b"Zealot-E2E-Root", new_root_key.as_mut_slice());
        hkdf_expand(&hkdf, b"Zealot-E2E-Chain", chain_key.as_mut_slice());
        hkdf_expand(
            &hkdf,
            b"Zealot-E2E-Next-Header",
            next_header_key.as_mut_slice(),
        );

        drop(dh_output);

        (new_root_key, chain_key, next_header_key)
    }

    /// Encrypts a message using the Double Ratchet algorithm.
    ///
    /// This performs the following steps:
    /// 1. Generates a message key from the sending chain
    /// 2. Encrypts the message header with the header key
    /// 3. Encrypts the message with the message key
    /// 4. Increments the sending chain message counter
    ///
    /// The session is left untouched if any step fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, Error> {
        let header = MessageHeader {
            public_key: self.public_key(),
            previous_chain_length: self.state.previous_sending_chain_length,
            message_number: self.state.sending_message_number,
        };
        let encrypted_header = self.encrypt_header(&header)?;

        // Advance a copy of the chain and only keep it once the message has
        // been produced, so a failure cannot leave the chain one step ahead of
        // the message counter.
        let mut sending_chain = self.state.sending_chain.clone();
        let message_key = sending_chain.next();
        let ciphertext = with_ad_buffer(|buffer| {
            buffer.extend_from_slice(self.state.ad.as_slice());
            buffer.extend_from_slice(&encrypted_header);
            Self::encrypt_message(message_key.as_bytes(), plaintext, buffer)
        })?;

        self.state.sending_chain = sending_chain;
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
            SysRng
                .try_fill_bytes(nonce_slice.as_mut_slice())
                .map_err(|_| Error::Random)?;

            let key = <&aes_gcm_siv::Key<Aes256GcmSiv>>::from(hk.as_ref());
            let cipher = Aes256GcmSiv::new(key);
            let nonce = <&Nonce>::from(nonce_slice.as_ref());

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

        let mut derived_material = Box::new([0u8; 44]);
        hkdf_expand(&hkdf, b"Zealot-E2E-Keys", derived_material.as_mut_slice());

        let ciphertext = Self::seal(&derived_material, plaintext, ad);

        derived_material.zeroize();

        ciphertext
    }

    fn seal(derived_material: &[u8; 44], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        let key = <&aes_gcm_siv::Key<Aes256GcmSiv>>::try_from(&derived_material[0..32])
            .map_err(|_| Error::Crypto("Invalid derived key length".to_string()))?;
        let cipher = Aes256GcmSiv::new(key);
        let nonce = <&Nonce>::try_from(&derived_material[32..44])
            .map_err(|_| Error::Crypto("Invalid derived nonce length".to_string()))?;

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
    /// The header is tried against, in order:
    /// 1. The current receiving header key. The message is then either the
    ///    next one on the current chain, one further ahead (the keys in between
    ///    are stored as skipped), or one that was skipped earlier.
    /// 2. The header key of each earlier chain that still has skipped keys
    ///    outstanding.
    /// 3. The next receiving header key, which means the peer has started a
    ///    new chain and a DH ratchet step is due.
    ///
    /// Every step works on copies of the keys it advances, and the session is
    /// only updated once the message body has authenticated. A message that
    /// fails for any reason leaves the session exactly as it was.
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>, Error> {
        if let Some(rhk) = self.state.receiving_header_key.as_deref()
            && let Some(header) = Self::decrypt_header(&message.header, rhk)
        {
            return self.decrypt_on_current_chain(message, &header);
        }

        if let Some(result) = self.decrypt_on_earlier_chain(message) {
            return result;
        }

        if let Some(nrhk) = self.state.next_receiving_header_key.as_deref()
            && let Some(header) = Self::decrypt_header(&message.header, nrhk)
        {
            return self.decrypt_with_dh_ratchet(message, &header);
        }

        Err(Error::HeaderKeyMismatch)
    }

    /// Decrypts a message whose header matched the current receiving chain.
    fn decrypt_on_current_chain(
        &mut self,
        message: &RatchetMessage,
        header: &MessageHeader,
    ) -> Result<Vec<u8>, Error> {
        let expected = self.state.receiving_message_number;
        let number = header.message_number;

        if number < expected {
            // Either skipped earlier and only arriving now, or a replay.
            let chain = self
                .state
                .receiving_header_key
                .as_deref()
                .and_then(|rhk| self.skipped_message_keys.position(rhk));
            return match chain {
                Some(chain) => self.decrypt_with_skipped_key(message, chain, number),
                None => Err(Error::DuplicateMessage),
            };
        }

        if number - expected > self.max_skip {
            return Err(Error::TooManySkipped);
        }

        let mut receiving_chain = self.state.receiving_chain.clone();
        let skipped = Self::advance_chain(&mut receiving_chain, expected, number);
        let message_key = receiving_chain.next();
        let plaintext = Self::open(&self.state.ad, &message_key, message)?;

        self.state.receiving_chain = receiving_chain;
        self.state.receiving_message_number = number.wrapping_add(1);
        if let Some(rhk) = self.state.receiving_header_key.as_deref() {
            for (number, key) in skipped {
                self.skipped_message_keys.insert(rhk, number, key);
            }
        }

        Ok(plaintext)
    }

    /// Tries the header against every earlier chain that still has skipped
    /// keys outstanding. Returns `None` if the header belongs to none of them.
    fn decrypt_on_earlier_chain(
        &mut self,
        message: &RatchetMessage,
    ) -> Option<Result<Vec<u8>, Error>> {
        let current = self.state.receiving_header_key.as_deref();

        let (chain, number) = self
            .skipped_message_keys
            .header_keys()
            // The current chain's header key has already been tried.
            .filter(|(_, header_key)| Some(*header_key) != current)
            .find_map(|(chain, header_key)| {
                Self::decrypt_header(&message.header, header_key)
                    .map(|header| (chain, header.message_number))
            })?;

        Some(self.decrypt_with_skipped_key(message, chain, number))
    }

    /// Decrypts a message with the stored key for `number` on a skipped chain,
    /// consuming the key on success.
    fn decrypt_with_skipped_key(
        &mut self,
        message: &RatchetMessage,
        chain: usize,
        number: u32,
    ) -> Result<Vec<u8>, Error> {
        let Some(message_key) = self.skipped_message_keys.get(chain, number) else {
            // The header authenticated under a chain we know, but its key was
            // already used (a replay) or has been evicted.
            return Err(Error::DuplicateMessage);
        };

        let plaintext = Self::open(&self.state.ad, message_key, message)?;
        self.skipped_message_keys.remove(chain, number);

        Ok(plaintext)
    }

    /// Decrypts the first message seen on a new chain, performing the DH
    /// ratchet step that chain calls for.
    fn decrypt_with_dh_ratchet(
        &mut self,
        message: &RatchetMessage,
        header: &MessageHeader,
    ) -> Result<Vec<u8>, Error> {
        let expected = self.state.receiving_message_number;
        let previous_chain_length = header.previous_chain_length;

        if previous_chain_length < expected {
            return Err(Error::Protocol("Invalid previous chain length".to_string()));
        }
        if previous_chain_length - expected > self.max_skip || header.message_number > self.max_skip
        {
            return Err(Error::TooManySkipped);
        }

        // Keys for whatever the peer sent on the chain being closed that has
        // not arrived yet. There is no such chain before the first message.
        let closing_keys = if self.state.receiving_header_key.is_some() {
            let mut closing_chain = self.state.receiving_chain.clone();
            Self::advance_chain(&mut closing_chain, expected, previous_chain_length)
        } else {
            Vec::new()
        };

        let mut next_state = self.state.clone();
        Self::dh_ratchet(&mut next_state, header)?;

        let opening_keys =
            Self::advance_chain(&mut next_state.receiving_chain, 0, header.message_number);
        let message_key = next_state.receiving_chain.next();
        next_state.receiving_message_number = header.message_number.wrapping_add(1);

        let plaintext = Self::open(&next_state.ad, &message_key, message)?;

        let previous_state = std::mem::replace(&mut self.state, next_state);
        if let Some(header_key) = previous_state.receiving_header_key.as_deref() {
            for (number, key) in closing_keys {
                self.skipped_message_keys.insert(header_key, number, key);
            }
        }
        if let Some(header_key) = self.state.receiving_header_key.as_deref() {
            for (number, key) in opening_keys {
                self.skipped_message_keys.insert(header_key, number, key);
            }
        }

        Ok(plaintext)
    }

    /// Advances `chain` from message number `from` up to, but not including,
    /// `until`, returning the message key of every number stepped over.
    ///
    /// Callers bound `until - from` by `max_skip` first.
    fn advance_chain(chain: &mut Chain, from: u32, until: u32) -> Vec<(u32, MessageKey)> {
        let count = until.saturating_sub(from) as usize;
        // More keys than the store holds would be evicted straight away, so
        // there is no point reserving room for them up front.
        let mut keys = Vec::with_capacity(count.min(MAX_SKIPPED_MESSAGE_KEYS));
        for number in from..until {
            keys.push((number, chain.next()));
        }
        keys
    }

    /// Authenticates and decrypts a message body.
    fn open(
        ad: &[u8; 64],
        message_key: &MessageKey,
        message: &RatchetMessage,
    ) -> Result<Vec<u8>, Error> {
        with_ad_buffer(|buffer| {
            buffer.extend_from_slice(ad);
            buffer.extend_from_slice(&message.header);
            Self::decrypt_message(message_key.as_bytes(), &message.ciphertext, buffer)
        })
    }

    /// Decrypts a message header using a specific header key.
    fn decrypt_header(encrypted_header: &[u8], hk: &[u8; 32]) -> Option<MessageHeader> {
        if encrypted_header.len() < 12 {
            return None;
        }

        let nonce = &encrypted_header[0..12];
        let ciphertext = &encrypted_header[12..];

        let key = <&aes_gcm_siv::Key<Aes256GcmSiv>>::from(hk);
        let cipher = Aes256GcmSiv::new(key);
        let nonce = <&Nonce>::try_from(nonce).ok()?;

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
    fn dh_ratchet(state: &mut RatchetState, header: &MessageHeader) -> Result<(), Error> {
        let seed = try_generate_random_seed()?;

        state.previous_sending_chain_length = state.sending_chain.index;

        // Update remote public key
        state.remote_dh_key_public = Some(header.public_key);

        // Reset message counters
        state.receiving_message_number = 0;
        state.sending_message_number = 0;

        state.receiving_header_key = state.next_receiving_header_key.clone();
        state.sending_header_key = Some(state.next_sending_header_key.clone());

        // Derive new receiving chain
        let dh_output = state.dh_pair.dh(&header.public_key);
        let (new_root_key, chain_key, next_header_key) =
            Self::kdf_rk_he(&state.root_key, dh_output);
        state.root_key = new_root_key;
        state.receiving_chain = Chain::new(chain_key);
        state.next_receiving_header_key = Some(next_header_key);

        // Generate new DH key pair
        state.dh_pair = X25519Secret::from(seed);

        // Derive new sending chain
        let dh_output = state.dh_pair.dh(&header.public_key);
        let (new_root_key, chain_key, next_header_key) =
            Self::kdf_rk_he(&state.root_key, dh_output);
        state.root_key = new_root_key;
        state.sending_chain = Chain::new(chain_key);
        state.next_sending_header_key = next_header_key;

        Ok(())
    }

    fn decrypt_message(key: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        let hkdf = Hkdf::<Sha256>::new(None, key.as_slice());

        let mut derived_material = Box::new([0u8; 44]);
        hkdf_expand(&hkdf, b"Zealot-E2E-Keys", derived_material.as_mut_slice());

        let plaintext = Self::unseal(&derived_material, ciphertext, ad);

        derived_material.zeroize();

        plaintext
    }

    fn unseal(derived_material: &[u8; 44], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        let aes_key = <&aes_gcm_siv::Key<Aes256GcmSiv>>::try_from(&derived_material[0..32])
            .map_err(|_| Error::Crypto("Invalid derived key length".to_string()))?;
        let cipher = Aes256GcmSiv::new(aes_key);
        let nonce = <&Nonce>::try_from(&derived_material[32..44])
            .map_err(|_| Error::Crypto("Invalid derived nonce length".to_string()))?;

        cipher
            .decrypt(
                nonce,
                aes_gcm_siv::aead::Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| Error::MessageDecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignedPreKey;

    fn create_test_drs() -> (DoubleRatchet, DoubleRatchet) {
        let b_spk = SignedPreKey::new(1);

        // For simplicity, let's create a dummy shared secret
        let shared_secret = generate_random_seed();

        let mut ad = Box::new([0u8; 64]);
        SysRng.try_fill_bytes(ad.as_mut_slice()).unwrap();

        // Initialize ratchets
        let a_dr = DoubleRatchet::initialize_for_alice(
            X3DHSharedSecret(shared_secret.clone()),
            &b_spk.public_key(),
            20,
            ad.clone(),
        );

        let b_dr = DoubleRatchet::initialize_for_bob(
            X3DHSharedSecret(shared_secret),
            b_spk.key_pair(),
            20,
            ad,
        );

        (a_dr, b_dr)
    }

    #[test]
    fn test_basic_communication() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let a_msg = "Hello, B!";
        let ciphertext = a_dr.encrypt(a_msg.as_bytes()).unwrap();

        let plaintext = b_dr.decrypt(&ciphertext).unwrap();
        assert_eq!(String::from_utf8(plaintext).unwrap(), a_msg);

        let b_msg = "Hello, A!";
        let ciphertext = b_dr.encrypt(b_msg.as_bytes()).unwrap();

        let plaintext = a_dr.decrypt(&ciphertext).unwrap();
        assert_eq!(String::from_utf8(plaintext).unwrap(), b_msg);
    }

    #[test]
    fn test_multiple_messages() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let msgs = vec![
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
            "Message 5",
        ];

        for msg in &msgs {
            let ciphertext = a_dr.encrypt(msg.as_bytes()).unwrap();
            let plaintext = b_dr.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), *msg);
        }

        let responses = vec!["Response 1", "Response 2", "Response 3"];

        for msg in &responses {
            let ciphertext = b_dr.encrypt(msg.as_bytes()).unwrap();
            let plaintext = a_dr.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), *msg);
        }
    }

    #[test]
    fn test_out_of_order_messages() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let msgs = vec![
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
            "Message 5",
        ];
        let mut ciphertexts = Vec::new();

        for msg in &msgs {
            ciphertexts.push(a_dr.encrypt(msg.as_bytes()).unwrap());
        }

        // Bob receives them out of order: 0, 2, 1, 4, 3
        let plaintext1 = b_dr.decrypt(&ciphertexts[0].clone()).unwrap();
        assert_eq!(String::from_utf8(plaintext1).unwrap(), msgs[0]);

        let plaintext3 = b_dr.decrypt(&ciphertexts[2].clone()).unwrap();
        assert_eq!(String::from_utf8(plaintext3).unwrap(), msgs[2]);

        let plaintext5 = b_dr.decrypt(&ciphertexts[4].clone()).unwrap();
        assert_eq!(String::from_utf8(plaintext5).unwrap(), msgs[4]);

        let plaintext2 = b_dr.decrypt(&ciphertexts[1].clone()).unwrap();
        assert_eq!(String::from_utf8(plaintext2).unwrap(), msgs[1]);

        let plaintext4 = b_dr.decrypt(&ciphertexts[3].clone()).unwrap();
        assert_eq!(String::from_utf8(plaintext4).unwrap(), msgs[3]);
    }

    #[test]
    fn test_dh_key_rotation() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        // Initial message exchange to establish the ratchet
        let a_msg = "Hello, B!";
        let ciphertext = a_dr.encrypt(a_msg.as_bytes()).unwrap();
        let plaintext = b_dr.decrypt(&ciphertext).unwrap();
        assert_eq!(String::from_utf8(plaintext).unwrap(), a_msg);

        // Save current ratchet state for later comparison
        let a_public_1 = a_dr.public_key();

        // Send multiple messages back and forth to trigger key rotation
        for i in 0..5 {
            let b_msg = format!("Message from B {i}");
            let ciphertext = b_dr.encrypt(b_msg.as_bytes()).unwrap();
            let plaintext = a_dr.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), b_msg);

            let a_msg = format!("Message from A {i}");
            let ciphertext = a_dr.encrypt(a_msg.as_bytes()).unwrap();
            let plaintext = b_dr.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), a_msg);
        }

        let a_public_2 = a_dr.public_key();
        assert_ne!(
            a_public_1.as_bytes(),
            a_public_2.as_bytes(),
            "dh keys should have rotated"
        );
    }

    #[test]
    fn test_large_message_payload() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let msg = vec![b'A'; 100 * 1024]; // 100Kb

        let ciphertext = a_dr.encrypt(&msg).unwrap();
        let plaintext = b_dr.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_empty_message_payload() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let msg = b"";
        let ciphertext = a_dr.encrypt(msg).unwrap();
        let plaintext = b_dr
            .decrypt(&ciphertext)
            .map_err(|err| {
                println!("{}", err.to_string());
                err
            })
            .unwrap();

        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_too_many_skipped_messages() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        b_dr.max_skip = 2;

        let mut ciphertexts = Vec::new();
        for i in 0..5 {
            let msg = format!("Message {i}");
            ciphertexts.push(a_dr.encrypt(msg.as_bytes()).unwrap());
        }

        // B receives first message
        let _ = b_dr.decrypt(&ciphertexts[0].clone()).unwrap();

        // B tries to decrypt message 4 (skipping 3 messages, which exceeds max_skip=2)
        let result = b_dr.decrypt(&ciphertexts[4].clone());
        assert_eq!(result, Err(Error::TooManySkipped));

        // But message 3 should work (skipping 2 messages)
        let result = b_dr.decrypt(&ciphertexts[3].clone());
        assert!(result.is_ok());
    }

    #[test]
    fn test_header_key_mismatch_error() {
        let (_, mut b_dr) = create_test_drs();
        // A second, unrelated pair has different header keys.
        let (mut a_dr, _) = create_test_drs();

        let wrong_ciphertext = a_dr.encrypt(b"Not for B").unwrap();

        assert_eq!(
            b_dr.decrypt(&wrong_ciphertext),
            Err(Error::HeaderKeyMismatch)
        );
    }

    #[test]
    fn test_duplicate_message_error() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let message = a_dr.encrypt(b"hello, world!").unwrap();

        assert!(b_dr.decrypt(&message).is_ok());
        assert_eq!(b_dr.decrypt(&message), Err(Error::DuplicateMessage));
    }

    #[test]
    fn test_tampered_ciphertext_error() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let mut message = a_dr.encrypt(b"hello, world!").unwrap();
        // The header still authenticates, but the body no longer does.
        message.ciphertext[0] ^= 0xFF;

        assert_eq!(b_dr.decrypt(&message), Err(Error::MessageDecryptionFailed));
    }

    #[test]
    fn test_skipped_message_keys_are_bounded() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        // Allow a single jump to skip more messages than the store can hold, so
        // the per-jump `max_skip` cap can't hide the total-store bound.
        let total = MAX_SKIPPED_MESSAGE_KEYS + 100;
        b_dr.max_skip = total as u32;

        // A sends messages numbered 0..=total, all on the same chain.
        let mut ciphertexts = Vec::with_capacity(total + 1);
        for i in 0..=total {
            let msg = format!("Message {i}");
            ciphertexts.push(a_dr.encrypt(msg.as_bytes()).unwrap());
        }

        // B jumps straight to the last message. Decrypting it generates skipped
        // keys for messages 0..total which must be bounded.
        let plaintexts = b_dr.decrypt(&ciphertexts[total].clone()).unwrap();
        assert_eq!(
            String::from_utf8(plaintexts).unwrap(),
            format!("Message {total}")
        );

        assert_eq!(b_dr.skipped_message_keys.len(), MAX_SKIPPED_MESSAGE_KEYS);

        // The oldest keys were evicted: message 0 can no longer be recovered,
        // while the newest retained key (message `total - 1`) still can.
        assert!(b_dr.decrypt(&ciphertexts[0].clone()).is_err());
        let recovered = b_dr.decrypt(&ciphertexts[total - 1].clone()).unwrap();
        assert_eq!(
            String::from_utf8(recovered).unwrap(),
            format!("Message {}", total - 1)
        );
    }

    #[test]
    fn test_skipped_keys_survive_a_dh_ratchet() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        // Chain 1: B only sees the first of three messages.
        let chain_1: Vec<_> = (0..3)
            .map(|i| a_dr.encrypt(format!("one {i}").as_bytes()).unwrap())
            .collect();
        assert_eq!(b_dr.decrypt(&chain_1[0]).unwrap(), b"one 0");

        // B replies, so A's next messages start a new chain.
        let reply = b_dr.encrypt(b"reply").unwrap();
        assert_eq!(a_dr.decrypt(&reply).unwrap(), b"reply");

        // Chain 2: B sees the second message first. That one message closes
        // chain 1 with two keys outstanding and skips one key on chain 2.
        let chain_2: Vec<_> = (0..2)
            .map(|i| a_dr.encrypt(format!("two {i}").as_bytes()).unwrap())
            .collect();
        assert_eq!(b_dr.decrypt(&chain_2[1]).unwrap(), b"two 1");
        assert_eq!(b_dr.skipped_message_keys.len(), 3);
        assert_eq!(b_dr.skipped_message_keys.header_keys().count(), 2);

        // Everything that was skipped still decrypts, in any order.
        assert_eq!(b_dr.decrypt(&chain_1[2]).unwrap(), b"one 2");
        assert_eq!(b_dr.decrypt(&chain_2[0]).unwrap(), b"two 0");

        // A replay on a closed chain that still has keys outstanding is
        // recognised for what it is.
        assert_eq!(b_dr.decrypt(&chain_1[2]), Err(Error::DuplicateMessage));

        assert_eq!(b_dr.decrypt(&chain_1[1]).unwrap(), b"one 1");
        assert_eq!(b_dr.skipped_message_keys.len(), 0);

        // With its last key used, the closed chain's header key is forgotten.
        assert_eq!(b_dr.decrypt(&chain_1[1]), Err(Error::HeaderKeyMismatch));
        // The current chain still reports replays as duplicates.
        assert_eq!(b_dr.decrypt(&chain_2[0]), Err(Error::DuplicateMessage));
    }

    #[test]
    fn test_skipped_key_is_kept_when_its_message_fails_to_authenticate() {
        let (mut a_dr, mut b_dr) = create_test_drs();

        let first = a_dr.encrypt(b"first").unwrap();
        let second = a_dr.encrypt(b"second").unwrap();
        assert_eq!(b_dr.decrypt(&second).unwrap(), b"second");

        let mut tampered = first.clone();
        tampered.ciphertext[0] ^= 0xFF;
        assert_eq!(b_dr.decrypt(&tampered), Err(Error::MessageDecryptionFailed));

        // The genuine message can still be delivered afterwards.
        assert_eq!(b_dr.decrypt(&first).unwrap(), b"first");
    }
}

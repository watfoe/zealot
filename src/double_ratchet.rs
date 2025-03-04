use crate::error::Error;
use crate::generate_random_seed;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, TryRngCore};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

const ROOT_KDF_INFO: &[u8] = b"DoubleRatchet_Root";
const CHAIN_KDF_INFO: &[u8] = b"DoubleRatchet_Chain";
const MESSAGE_KDF_INFO: &[u8] = b"DoubleRatchet_Message";

const NONCE_SIZE: usize = 12; // AES-GCM uses 12-byte (96-bit) nonces

/// Ratchet chain for deriving keys
struct Chain {
    chain_key: [u8; 32],
    index: u32,
}

impl Chain {
    fn new(chain_key: [u8; 32]) -> Self {
        Self {
            chain_key,
            index: 0,
        }
    }

    /// Advances the chain and returns a message key
    fn next(&mut self) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);

        let mut chain_key = [0u8; 32];
        hkdf.expand(&[CHAIN_KDF_INFO, &[1]].concat(), &mut chain_key)
            .expect("HKDF expansion failed for chain key");

        let mut message_key = [0u8; 32];
        hkdf.expand(&[MESSAGE_KDF_INFO, &[2]].concat(), &mut message_key)
            .expect("HKDF expansion failed for message key");

        // Update the chain state
        self.chain_key = chain_key;
        self.index += 1;

        message_key
    }

    fn get_index(&self) -> u32 {
        self.index
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

/// Header for a ratchet message
#[derive(Clone, Copy)]
pub struct MessageHeader {
    public_key: PublicKey,
    previous_chain_length: u32,
    message_number: u32,
}

impl MessageHeader {
    pub fn serialize(&self) -> Vec<u8> {
        // Public key (32 bytes) + Previous chain length (4 bytes) + Message number (4 bytes)
        let mut bytes = Vec::with_capacity(32 + 4 + 4);

        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        bytes.extend_from_slice(&self.message_number.to_be_bytes());

        bytes
    }

    /// Deserialize a header from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 32 + 4 + 4 {
            return Err(Error("Invalid header length".to_string()));
        }

        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&bytes[0..32]);

        let mut pn_bytes = [0u8; 4];
        pn_bytes.copy_from_slice(&bytes[32..36]);

        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&bytes[36..40]);

        let public_key = PublicKey::from(dh_bytes);
        let previous_chain_length = u32::from_be_bytes(pn_bytes);
        let message_number = u32::from_be_bytes(n_bytes);

        Ok(MessageHeader {
            public_key,
            previous_chain_length,
            message_number,
        })
    }
}

/// Complete ratchet message with header and ciphertext
#[derive(Clone)]
pub struct RatchetMessage {
    header: MessageHeader,
    ciphertext: Vec<u8>,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();

        // Clear skipped message keys
        for (_, key) in self.skipped_message_keys.drain() {
            let mut key_copy = key;
            key_copy.zeroize();
        }
    }
}

/// Double Ratchet implementation
pub struct DoubleRatchet {
    dh_pair: StaticSecret,
    dh_remote_public: Option<PublicKey>,

    root_key: [u8; 32],
    sending_chain: Chain,
    receiving_chain: Chain,

    // Message counters
    previous_sending_chain_length: u32,
    sending_message_number: u32,
    receiving_message_number: u32,

    // Map<(ratchet_public_key, message_number): message_key>
    skipped_message_keys: HashMap<(PublicKey, u32), [u8; 32]>,
    max_skip: u32,
}

impl DoubleRatchet {
    /// Initialize a ratchet as the first sender (Alice)
    pub fn initialize_as_first_sender(
        shared_secret: &[u8],
        receiver_public_key: &PublicKey,
    ) -> Self {
        let dh_pair = StaticSecret::from(generate_random_seed().unwrap());

        // Create root key from the shared secret
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&shared_secret[0..32]); // Use first 32 bytes

        // Perform initial DH and KDF
        let dh_output = dh_pair.diffie_hellman(receiver_public_key);
        let (new_root_key, chain_key) = Self::kdf_rk(&root_key, dh_output);

        // Initialize chains
        let sending_chain = Chain::new(chain_key);
        let receiving_chain = Chain::new([0u8; 32]); // Will be initialized on first message

        Self {
            dh_pair,
            dh_remote_public: Some(*receiver_public_key),
            root_key: new_root_key,
            sending_chain,
            receiving_chain,
            previous_sending_chain_length: 0,
            sending_message_number: 0,
            receiving_message_number: 0,
            skipped_message_keys: HashMap::new(),
            max_skip: 100, // Maximum number of message keys to skip
        }
    }

    /// Initialize a ratchet as the first receiver (Bob)
    pub fn initialize_as_first_receiver(shared_secret: &[u8], own_dh_pair: StaticSecret) -> Self {
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&shared_secret[0..32]); // Use first 32 bytes

        // Empty chains - will be populated on first message
        let sending_chain = Chain::new([0u8; 32]);
        let receiving_chain = Chain::new([0u8; 32]);

        Self {
            dh_pair: own_dh_pair,
            dh_remote_public: None, // Will be set when first message arrives
            root_key,
            sending_chain,
            receiving_chain,
            previous_sending_chain_length: 0,
            sending_message_number: 0,
            receiving_message_number: 0,
            skipped_message_keys: HashMap::new(),
            max_skip: 100,
        }
    }

    /// Get the current dh ratchet public key
    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::from(&self.dh_pair)
    }

    /// Key derivation function for the root key
    fn kdf_rk(root_key: &[u8; 32], mut dh_output: SharedSecret) -> ([u8; 32], [u8; 32]) {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), &dh_output.to_bytes());

        let mut new_root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];

        hkdf.expand(&[ROOT_KDF_INFO, &[1]].concat(), &mut new_root_key)
            .expect("HKDF expansion failed for root key");

        hkdf.expand(&[ROOT_KDF_INFO, &[2]].concat(), &mut chain_key)
            .expect("HKDF expansion failed for chain key");

        dh_output.zeroize();

        (new_root_key, chain_key)
    }

    /// Performs a DH ratchet step
    fn dh_ratchet(&mut self, header: &MessageHeader) -> Result<(), Error> {
        self.previous_sending_chain_length = self.sending_chain.get_index();

        // Update remote public key
        self.dh_remote_public = Some(header.public_key);

        // Reset message counters
        self.receiving_message_number = 0;
        self.sending_message_number = 0;

        // Derive new receiving chain
        let dh_output = self.dh_pair.diffie_hellman(&header.public_key);
        let (new_root_key, chain_key) = Self::kdf_rk(&self.root_key, dh_output);
        self.root_key = new_root_key;
        self.receiving_chain = Chain::new(chain_key);

        // Generate new DH key pair
        self.dh_pair = StaticSecret::from(generate_random_seed()?);

        // Derive new sending chain
        let dh_output = self.dh_pair.diffie_hellman(&header.public_key);
        let (new_root_key, chain_key) = Self::kdf_rk(&self.root_key, dh_output);
        self.root_key = new_root_key;
        self.sending_chain = Chain::new(chain_key);

        Ok(())
    }

    /// Encrypt a message
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RatchetMessage, Error> {
        let header = MessageHeader {
            public_key: self.get_public_key(),
            previous_chain_length: self.previous_sending_chain_length,
            message_number: self.sending_message_number,
        };

        let mut ad = Vec::with_capacity(associated_data.len() + header.serialize().len());
        ad.extend_from_slice(associated_data);
        ad.extend_from_slice(&header.serialize());

        // Increment message number
        self.sending_message_number += 1;

        let message_key = self.sending_chain.next();
        let ciphertext = Self::encrypt_message(&message_key, plaintext, &ad)?;

        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt a message
    pub fn decrypt(
        &mut self,
        message: RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut ad = Vec::with_capacity(associated_data.len() + message.header.serialize().len());
        ad.extend_from_slice(associated_data);
        ad.extend_from_slice(&message.header.serialize());

        // Try to decrypt with skipped message keys
        if let Some(plaintext) = self.try_skipped_message_keys(&message, &ad)? {
            return Ok(plaintext);
        }

        // Check if ratchet public key has changed
        if self.dh_remote_public.is_none()
            || message.header.public_key != self.dh_remote_public.unwrap()
        {
            // Ratchet step - DH key has changed
            self.dh_ratchet(&message.header)?;
        }

        // Skip ahead if needed
        if message.header.message_number > self.receiving_message_number {
            self.skip_message_keys(message.header.message_number)?;
        }

        // Get the current message key
        let message_key = self.receiving_chain.next();
        self.receiving_message_number += 1;

        let plaintext = Self::decrypt_message(&message_key, &message.ciphertext, &ad)?;

        Ok(plaintext)
    }

    /// Try to decrypt with skipped message keys
    fn try_skipped_message_keys(
        &mut self,
        message: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        if let Some(dhr) = self.dh_remote_public {
            if let Some(mk) = self
                .skipped_message_keys
                .remove(&(dhr, message.header.message_number))
            {
                let plaintext = Self::decrypt_message(&mk, &message.ciphertext, associated_data)?;
                return Ok(Some(plaintext));
            }
        }

        Ok(None)
    }

    /// Skip message keys to handle out-of-order messages
    fn skip_message_keys(&mut self, until: u32) -> Result<(), Error> {
        if until - self.receiving_message_number > self.max_skip {
            return Err(Error("Too many skipped messages".to_string()));
        }

        while self.receiving_message_number < until {
            let message_key = self.receiving_chain.next();
            let public_key = self.dh_remote_public.unwrap();

            self.skipped_message_keys
                .insert((public_key, self.receiving_message_number), message_key);
            self.receiving_message_number += 1;
        }

        Ok(())
    }

    /// Encrypt a message
    fn encrypt_message(
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(&key);

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.try_fill_bytes(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            },
        ) {
            Ok(ciphertext) => {
                // Prepend the nonce to the ciphertext
                let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Decrypt a message
    fn decrypt_message(
        key: &[u8; 32],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Ensure the ciphertext is at least as long as the nonce
        if ciphertext.len() < NONCE_SIZE {
            return Err(Error("Invalid ciphertext length".to_string()));
        }

        let nonce = Nonce::from_slice(&ciphertext[0..NONCE_SIZE]);

        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(aes_key);

        match cipher.decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &ciphertext[NONCE_SIZE..],
                aad: associated_data,
            },
        ) {
            Ok(plaintext) => Ok(plaintext),
            Err(err) => Err(Error(format!("Decoding: {}", err.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey, X3DH};

    fn create_ratchets() -> (DoubleRatchet, DoubleRatchet) {
        let bob_spk = SignedPreKey::new(1);

        // For simplicity, let's create a dummy shared secret
        let mut shared_secret = [0u8; 32];
        OsRng.try_fill_bytes(&mut shared_secret).unwrap();

        // Initialize ratchets
        let alice_ratchet =
            DoubleRatchet::initialize_as_first_sender(&shared_secret, &bob_spk.get_public_key());

        let bob_ratchet =
            DoubleRatchet::initialize_as_first_receiver(&shared_secret, bob_spk.get_pre_key_pair());

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
        let decrypted = bob_ratchet.decrypt(encrypted_message, b"AD").unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), alice_message);

        // Bob responds to Alice
        let bob_message = "Hello, Alice!";
        let encrypted_response = bob_ratchet.encrypt(bob_message.as_bytes(), b"AD").unwrap();

        // Alice decrypts Bob's response
        let decrypted_response = alice_ratchet.decrypt(encrypted_response, b"AD").unwrap();
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
            let decrypted = bob_ratchet.decrypt(encrypted, b"AD").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), *msg);
        }

        // Send multiple messages from Bob to Alice
        let responses = vec!["Response 1", "Response 2", "Response 3"];

        for msg in &responses {
            let encrypted = bob_ratchet.encrypt(msg.as_bytes(), b"AD").unwrap();
            let decrypted = alice_ratchet.decrypt(encrypted, b"AD").unwrap();
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
            .decrypt(encrypted_messages[0].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted1).unwrap(), messages[0]);

        let decrypted3 = bob_ratchet
            .decrypt(encrypted_messages[2].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted3).unwrap(), messages[2]);

        let decrypted2 = bob_ratchet
            .decrypt(encrypted_messages[1].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted2).unwrap(), messages[1]);

        let decrypted5 = bob_ratchet
            .decrypt(encrypted_messages[4].clone(), b"AD")
            .unwrap();
        assert_eq!(String::from_utf8(decrypted5).unwrap(), messages[4]);

        let decrypted4 = bob_ratchet
            .decrypt(encrypted_messages[3].clone(), b"AD")
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
        let decrypted = bob_ratchet.decrypt(encrypted_message, b"AD").unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), alice_message);

        // Save current ratchet state for later comparison
        let alice_initial_public = alice_ratchet.get_public_key();

        // Send multiple messages back and forth to trigger key rotation
        for i in 0..5 {
            // Bob to Alice
            let bob_msg = format!("Message from Bob {}", i);
            let encrypted = bob_ratchet.encrypt(bob_msg.as_bytes(), b"AD").unwrap();
            let decrypted = alice_ratchet.decrypt(encrypted, b"AD").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), bob_msg);

            // Alice to Bob
            let alice_msg = format!("Message from Alice {}", i);
            let encrypted = alice_ratchet.encrypt(alice_msg.as_bytes(), b"AD").unwrap();
            let decrypted = bob_ratchet.decrypt(encrypted, b"AD").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), alice_msg);
        }

        // Verify that Alice's public key has changed (indicating DH ratchet turned)
        let alice_final_public = alice_ratchet.get_public_key();
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
        let alice_public_key = alice_x3dh_result.get_public_key();
        // 4. Alice initializes her Double Ratchet with the shared secret
        let mut alice_ratchet = DoubleRatchet::initialize_as_first_sender(
            &alice_x3dh_result.get_shared_secret(),
            &bob_bundle.get_signed_pre_key_public(),
        );
        // 5. Bob processes Alice's initiation
        let bob_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_public_key,
            )
            .unwrap();
        // 6. Bob initializes his Double Ratchet with the shared secret
        let mut bob_ratchet = DoubleRatchet::initialize_as_first_receiver(
            &bob_shared_secret,
            bob_signed_pre_key.get_pre_key_pair(),
        );
        // 7. Test message exchange
        let message = "This is a secure message using X3DH + Double Ratchet!";
        let encrypted = alice_ratchet.encrypt(message.as_bytes(), b"AD").unwrap();
        let decrypted = bob_ratchet.decrypt(encrypted, b"AD").unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), message);

        // 8. Test reply
        let reply = "Received your message securely!";
        let encrypted_reply = bob_ratchet.encrypt(reply.as_bytes(), b"AD").unwrap();
        let decrypted_reply = alice_ratchet.decrypt(encrypted_reply, b"AD").unwrap();

        assert_eq!(String::from_utf8(decrypted_reply).unwrap(), reply);
    }

    #[test]
    fn test_large_message() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        // Create a large message (100KB)
        let large_message = vec![b'A'; 100 * 1024];

        // Encrypt and decrypt
        let encrypted = alice_ratchet.encrypt(&large_message, b"AD").unwrap();
        let decrypted = bob_ratchet.decrypt(encrypted, b"AD").unwrap();

        assert_eq!(decrypted, large_message);
    }

    #[test]
    fn test_empty_message() {
        let (mut alice_ratchet, mut bob_ratchet) = create_ratchets();

        let empty_message = b"";
        let encrypted = alice_ratchet.encrypt(empty_message, b"AD").unwrap();
        let decrypted = bob_ratchet
            .decrypt(encrypted, b"AD")
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
            .decrypt(encrypted_messages[0].clone(), b"AD")
            .unwrap();

        // Bob tries to decrypt message 4 (skipping 3 messages, which exceeds max_skip=2)
        let result = bob_ratchet.decrypt(encrypted_messages[4].clone(), b"AD");
        assert!(result.is_err());

        // But message 3 should work (skipping 2 messages)
        let result = bob_ratchet.decrypt(encrypted_messages[3].clone(), b"AD");
        assert!(result.is_ok());
    }
}

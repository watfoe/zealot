//! # A naive Signal Protocol Implementation
//!
//! A Rust implementation of the Signal Protocol for secure, end-to-end encrypted messaging,
//! including X3DH (Extended Triple Diffie-Hellman) key agreement and the Double Ratchet
//! algorithm for message encryption.
//!
//! ## Features
//!
//! - **X3DH Key Agreement**: Establishes shared secrets between parties asynchronously
//! - **Double Ratchet Algorithm**: Provides forward secrecy and break-in recovery
//! - **Identity Key Management**: Long-term identity keys for authentication
//! - **Pre-Key Bundles**: Signed pre-keys and one-time pre-keys for session establishment
//! - **Session Management**: Secure communication channels between users
//! - **Account Management**: User identity, key rotation, and session tracking
//!
//! ## Security Properties
//!
//! This implementation provides:
//!
//! - **Forward Secrecy**: Compromise of current keys doesn't compromise past messages
//! - **Break-in Recovery**: Compromise of current keys doesn't compromise future messages
//! - **Authentication**: Verification of message sender identity
//! - **Asynchronous Operation**: Secure communication even when recipients are offline
//! - **Plausible Deniability**: Messages cannot be cryptographically proven to come from a specific sender
//!
//! ## Usage Examples
//!
//! ### Creating Accounts and Establishing Sessions
//!
//! ```rust
//! use zealot::{Account, AccountConfig, PreKeyBundle};
//! use std::time::Duration;
//!
//! // Create Alice's account
//! let config = AccountConfig {
//!     signed_pre_key_rotation_interval: Duration::from_secs(7 * 24 * 60 * 60), // 1 week
//!     min_one_time_pre_keys: 10,
//!     max_one_time_pre_keys: 100,
//!     max_skipped_messages: 100,
//!     protocol_info: b"com.example.secureapp".to_vec(),
//! };
//! let mut alice = Account::new(Some(config));
//!
//! // Create Bob's account
//! let mut bob = Account::new(None); // Use default config
//!
//! // Bob gets his pre-key bundle to publish
//! let (bob_bundle, bob_one_time_keys) = bob.prekey_bundle();
//!
//! // Alice creates a session with Bob
//! let session_id = alice.create_outbound_session(&bob_bundle)
//!     .expect("Failed to create session");
//!
//! // Alice can now use this session to send encrypted messages to Bob
//! ```
//!
//! ### Sending and Receiving Messages
//!
//! ```rust
//! # use zealot::{Account, AccountConfig, PreKeyBundle, RatchetMessage};
//! # let mut alice = Account::new(None);
//! # let mut bob = Account::new(None);
//! # let (bob_bundle, _) = bob.prekey_bundle();
//! # let alice_session_id = alice.create_outbound_session(&bob_bundle).unwrap();
//!
//! // Alice encrypts a message for Bob
//! let message = "Hello Bob! This is a secure message.";
//! let associated_data = b"message-id-12345"; // Additional authenticated data
//!
//! let encrypted_message = {
//!     let alice_session = alice.session_mut(&alice_session_id)
//!         .expect("Session not found");
//!
//!     alice_session.encrypt(message.as_bytes(), associated_data)
//!         .expect("Encryption failed")
//! };
//!
//! // Bob processes Alice's initial message and creates a session
//! // This would normally happen after receiving Alice's message over a network
//! let alice_identity_key = alice.identity_key().public_dh_key();
//! let alice_ephemeral_key = alice.session(&alice_session_id).unwrap().public_initiator_ephemeral_key().unwrap();
//!
//! let bob_session_id = bob.create_inbound_session(
//!     &alice_identity_key,
//!     &alice_ephemeral_key,
//!     bob_bundle.signed_pre_key_id(),
//!     None // Optional one-time pre-key ID
//! ).expect("Failed to process session initiation");
//!
//! // Bob decrypts Alice's message
//! let decrypted_message = {
//!     let bob_session = bob.session_mut(&bob_session_id)
//!         .expect("Session not found");
//!
//!     bob_session.decrypt(&encrypted_message, associated_data)
//!         .expect("Decryption failed")
//! };
//!
//! assert_eq!(
//!     String::from_utf8(decrypted_message).unwrap(),
//!     message
//! );
//!
//! // Bob can now send encrypted replies to Alice
//! let reply = "Hello Alice! I received your message.";
//!
//! let encrypted_reply = {
//!     let bob_session = bob.session_mut(&bob_session_id)
//!         .expect("Session not found");
//!
//!     bob_session.encrypt(reply.as_bytes(), associated_data)
//!         .expect("Encryption failed")
//! };
//!
//! // Alice decrypts Bob's reply
//! let decrypted_reply = {
//!     let alice_session = alice.session_mut(&alice_session_id)
//!         .expect("Session not found");
//!
//!     alice_session.decrypt(&encrypted_reply, associated_data)
//!         .expect("Decryption failed")
//! };
//!
//! assert_eq!(
//!     String::from_utf8(decrypted_reply).unwrap(),
//!     reply
//! );
//! ```
//!
//! ### Handling Out-of-Order Messages
//!
//! ```rust
//! # use zealot::{Account, RatchetMessage};
//! # let mut alice = Account::new(None);
//! # let mut bob = Account::new(None);
//! # let (bob_bundle, _) = bob.prekey_bundle();
//! # let alice_session_id = alice.create_outbound_session(&bob_bundle).unwrap();
//! # let alice_identity_key = alice.identity_key().public_dh_key();
//! # let alice_ephemeral_key = alice.session(&alice_session_id).unwrap().public_initiator_ephemeral_key().unwrap();
//! # let bob_session_id = bob.create_inbound_session(
//! #     &alice_identity_key,
//! #     &alice_ephemeral_key,
//! #     bob_bundle.signed_pre_key_id(),
//! #     None
//! # ).unwrap();
//!
//! // Alice sends multiple messages
//! let alice_session = alice.session_mut(&alice_session_id).unwrap();
//! let message1 = alice_session.encrypt(b"Message 1", b"AD").unwrap();
//! let message2 = alice_session.encrypt(b"Message 2", b"AD").unwrap();
//! let message3 = alice_session.encrypt(b"Message 3", b"AD").unwrap();
//!
//! // Bob receives them out of order: 1, 3, 2
//! let bob_session = bob.session_mut(&bob_session_id).unwrap();
//!
//! // Decrypt message 1
//! let decrypted1 = bob_session.decrypt(&message1, b"AD").unwrap();
//! assert_eq!(decrypted1, b"Message 1");
//!
//! // Decrypt message 3 (out of order)
//! let decrypted3 = bob_session.decrypt(&message3, b"AD").unwrap();
//! assert_eq!(decrypted3, b"Message 3");
//!
//! // Decrypt message 2 (which was delayed)
//! let decrypted2 = bob_session.decrypt(&message2, b"AD").unwrap();
//! assert_eq!(decrypted2, b"Message 2");
//!
//! // The Double Ratchet algorithm correctly handles out-of-order messages
//! // as long as they are within the configured max_skip window
//! ```
//!
//! ### End-to-End Encryption Architecture
//!
//! This library implements all the cryptographic components needed for a secure
//! messaging application, but you will need to provide:
//!
//! 1. **Network Transport**: Sending and receiving encrypted messages
//! 2. **Key Distribution**: Publishing and retrieving pre-key bundles
//! 3. **Message Serialization**: Converting messages to/from wire format
//! 4. **User Authentication**: Verifying user identities
//! 5. **Key Storage**: Securely storing private keys and session state
//!
//! ## Protocol Details
//!
//! This implementation follows the Signal Protocol specifications:
//!
//! - [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
//! - [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
//!
//! ## Security Considerations
//!
//! While this library implements the cryptographic protocols correctly, secure
//! messaging applications should also consider:
//!
//! - **Key Verification**: Out-of-band verification of identity keys
//! - **Secure Storage**: Protection of private keys and session state
//! - **Metadata Protection**: Encrypting or minimizing metadata
//! - **Perfect Forward Secrecy**: Regular key rotation
//! - **Secure Random Number Generation**: Using a cryptographically secure RNG
//!
//! The security of the application depends not only on the cryptographic protocols
//! but also on the security of the surrounding infrastructure.

mod crypto;
pub use crypto::*;

mod identity_key;
pub use identity_key::*;

mod one_time_pre_key;
pub use one_time_pre_key::OneTimePreKey;

mod pre_key;
pub use pre_key::*;

mod x3dh;
pub use x3dh::*;

mod ratchet_message;
pub use ratchet_message::*;

mod ratchet;
pub use ratchet::*;

mod error;
pub use error::Error;

mod account;
pub use account::Account;

mod config;
pub use config::AccountConfig;

mod session;
pub use session::*;

mod proto;
pub use proto::*;

pub(crate) mod chain;
pub(crate) mod state;

# zealot

A Rust implementation of the Signal Protocol for secure, end-to-end encrypted messaging, including X3DH (Extended Triple Diffie-Hellman) key agreement and the Double Ratchet algorithm for message encryption.

## Features

- **X3DH Key Agreement**: Establishes shared secrets between parties asynchronously
- **Double Ratchet Algorithm**: Provides forward secrecy and break-in recovery
- **Identity Key Management**: Long-term identity keys for authentication
- **Pre-Key Bundles**: Signed pre-keys and one-time pre-keys for session establishment
- **Independent Session Management**: Sessions can be managed separately from accounts
- **Granular Serialization**: Accounts and sessions can be serialized independently
- **Concurrent Message Processing**: Multiple sessions can encrypt/decrypt concurrently

## Security Properties

This implementation provides:

- **Forward Secrecy**: Compromise of current keys doesn't compromise past messages
- **Break-in Recovery**: Compromise of current keys doesn't compromise future messages
- **Authentication**: Verification of message sender identity
- **Asynchronous Operation**: Secure communication even when recipients are offline
- **Plausible Deniability**: Messages cannot be cryptographically proven to come from a specific sender

## Usage Example

```rust
use zealot::{Account, AccountConfig, X3DHPublicKeys};
use std::time::Duration;

// Create Alice's account
let config = AccountConfig {
    spk_rotation_interval: Duration::from_secs(7 * 24 * 60 * 60), // 1 week
    min_otpks: 5,
    max_otpks: 10,
    max_spks: 2,
    max_skipped_messages: 10,
    protocol_info: b"com.example.secureapp".to_vec(),
};
let mut alice = Account::new(Some(config.clone()));

// Create Bob's account
let mut bob = Account::new(Some(config)); // Use default config

// Bob publishes his pre-key bundle: his identity key, his signed pre-key, and
// the pool of one-time pre-keys he currently has available.
let bob_bundle = bob.prekey_bundle();

// A server holds that bundle and answers each fetch with a single one-time
// pre-key claimed from the pool, never handing the same one out twice. That
// allocation is what makes a one-time pre-key one-time, and it belongs to
// your transport rather than to this crate, so you assemble the result here.
let (otpk_id, otpk_public) = bob_bundle
    .otpks_public
    .iter()
    .next()
    .map(|(id, key)| (*id, key.to_bytes()))
    .expect("Bob published at least one one-time pre-key");

let bob_x3dh_keys = X3DHPublicKeys::try_from(
    bob_bundle.ik_public.to_bytes(),
    bob_bundle.signing_key_public.to_bytes(),
    (bob_bundle.spk_public.0, bob_bundle.spk_public.1.to_bytes()),
    bob_bundle.signature.to_bytes(),
    Some((otpk_id, otpk_public)),
).expect("Bob's bundle should be well formed");

// Alice creates a session with Bob
let mut alice_session = alice.create_outbound_session(&bob_x3dh_keys)
    .expect("Failed to create session");

// Bob processes Alice's session initiation
let outbound_x3dh_keys = alice_session.x3dh_keys().unwrap();
let mut bob_session = bob.create_inbound_session(
    alice.ik_public(),
    &outbound_x3dh_keys
).unwrap();

// Alice encrypts a message
let message = "Hello Bob! This is a secure message.";
let encrypted_message = alice_session.encrypt(message.as_bytes())
    .expect("Encryption failed");

// Bob decrypts the message
let decrypted_message = bob_session.decrypt(&encrypted_message)
    .expect("Decryption failed");

assert_eq!(String::from_utf8(decrypted_message).unwrap(), message);
```

## Protocol Details

This implementation follows the Signal Protocol specifications:

- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)

## Security Considerations

While this library implements the cryptographic protocols correctly, secure messaging applications should also consider:

- **Key Verification**: Out-of-band verification of identity keys
- **Secure Storage**: Protection of private keys and session state
- **Metadata Protection**: Encrypting or minimizing metadata
- **Perfect Forward Secrecy**: Regular key rotation and session refresh

## End-to-End Encryption Architecture

This library implements all the cryptographic components needed for a secure messaging application, but you will need to provide:

1. **Network Transport**: Sending and receiving encrypted messages
2. **Key Distribution**: Publishing and retrieving pre-key bundles
3. **Message Serialization**: Converting messages to/from wire format
4. **User Authentication**: Verifying user identities
5. **Key Storage**: Securely storing private keys and session state

## Why this library exists

Zealot is not an attempt to replace established Signal Protocol implementations such as [libsignal](https://github.com/signalapp/libsignal) or [vodozemac](https://github.com/matrix-org/vodozemac), nor is it a claim that writing one’s own crypto is generally advisable. In fact, experience with this project has reinforced how easy it is to make subtle, security-relevant mistakes.

The primary motivation behind Zealot was deep, end-to-end understanding of the protocol that sits at the absolute core of a secure messaging system. Because encryption is tightly coupled to session state, durability, failure handling, and client behavior in real applications, treating it purely as a black-box dependency was not sufficient for the goals of our project.

Zealot follows the official Signal specifications and pseudocode, relies on standard cryptographic primitives (rather than inventing new ones), and is best understood as an engineering implementation of a well-documented protocol rather than a novel cryptosystem.

## ⚠️ Security Notice

**THIS LIBRARY HAS NOT UNDERGONE A SECURITY AUDIT. USE AT YOUR OWN RISK!**

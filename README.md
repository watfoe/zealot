# zealot

A Rust implementation of the Signal Protocol for secure, end-to-end encrypted messaging, including X3DH (Extended Triple Diffie-Hellman) key agreement and the Double Ratchet algorithm for message encryption.

## Features

- **X3DH Key Agreement**: Establishes shared secrets between parties asynchronously
- **Double Ratchet Algorithm**: Provides forward secrecy and break-in recovery
- **Identity Key Management**: Long-term identity keys for authentication
- **Pre-Key Bundles**: Signed pre-keys and one-time pre-keys for session establishment

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
let mut alice = Account::new(Some(config.clone())).unwrap();

// Create Bob's account
let mut bob = Account::new(Some(config)).unwrap();

// Bob publishes his pre-key bundle
let bob_bundle = bob.prekey_bundle();
let bob_x3dh_keys = X3DHPublicKeys::from(&bob_bundle);

// Alice creates a session with Bob
let mut alice_session = alice.create_outbound_session(&bob_x3dh_keys)
    .expect("Failed to create session");

// Bob processes Alice's session initiation
let outbound_x3dh_keys = alice_session.x3dh_keys().unwrap();
let mut bob_session = bob.create_inbound_session(
    &alice.ik_public(),
    &outbound_x3dh_keys
).unwrap();

// Alice encrypts a message
let message = "Hello Bob! This is a secure message.";
let associated_data = b"message-id-12345";
let encrypted_message = alice_session.encrypt(message.as_bytes(), associated_data)
    .expect("Encryption failed");

// Bob decrypts the message
let decrypted_message = bob_session.decrypt(&encrypted_message, associated_data)
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

## ⚠️ Security Notice

**This library has not undergone a security audit.**

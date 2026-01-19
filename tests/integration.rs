#[cfg(test)]
mod integration_tests {
    use std::time::Duration;
    use zealot::{Account, AccountConfig, Session, X3DHPublicKeys};

    #[test]
    fn test_full_protocol_flow() {
        println!("Step 1: Creating accounts for Alice and Bob...");
        let alice_account = Account::new(None);
        let mut bob_account = Account::new(None);

        println!("Step 2: Bob publishes his pre-key bundle...");
        let bob_bundle = bob_account.prekey_bundle();
        let bob_x3dh_keys = X3DHPublicKeys::from(&bob_bundle);

        println!("Step 3: Verifying Bob's pre-key bundle...");
        assert!(bob_x3dh_keys.verify().is_ok(), "Bundle verification failed");

        println!("Step 4: Alice creates outbound session to Bob...");
        let mut alice_session = alice_account
            .create_outbound_session(&bob_x3dh_keys)
            .unwrap();

        println!("Step 5: Bob creates inbound session from Alice...");
        let outbound_x3dh_keys = alice_session.x3dh_keys().unwrap();
        let mut bob_session = bob_account
            .create_inbound_session(&alice_account.ik_public(), &outbound_x3dh_keys)
            .unwrap();

        println!("Step 6: Alice sends first message...");
        let alice_message_1 = "Hey Bob, this is a secure message!";
        let alice_ad_1 = b"Alice->Bob:1";
        let encrypted_message_1 = alice_session
            .encrypt(alice_message_1.as_bytes(), alice_ad_1)
            .unwrap();

        println!("Step 7: Bob decrypts Alice's first message...");
        let decrypted_message_1 = bob_session
            .decrypt(&encrypted_message_1, alice_ad_1)
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_message_1).unwrap(),
            alice_message_1
        );

        println!("Step 8: Bob replies to Alice...");
        let bob_message_1 = "Hi Alice! I received your secure message.";
        let bob_ad_1 = b"Bob->Alice:1";
        let encrypted_reply_1 = bob_session
            .encrypt(bob_message_1.as_bytes(), bob_ad_1)
            .unwrap();

        println!("Step 9: Alice decrypts Bob's reply...");
        let decrypted_reply_1 = alice_session.decrypt(&encrypted_reply_1, bob_ad_1).unwrap();
        assert_eq!(String::from_utf8(decrypted_reply_1).unwrap(), bob_message_1);

        println!("Step 10: Testing session serialization and restoration...");
        let alice_session_data = alice_session.serialize().unwrap();
        let bob_session_data = bob_session.serialize().unwrap();

        let mut alice_restored = Session::deserialize(&alice_session_data).unwrap();
        let mut bob_restored = Session::deserialize(&bob_session_data).unwrap();

        println!("Step 11: Testing continued communication after restoration...");
        let alice_message_2 = "How's the weather there?";
        let alice_ad_2 = b"Alice->Bob:2";
        let encrypted_message_2 = alice_restored
            .encrypt(alice_message_2.as_bytes(), alice_ad_2)
            .unwrap();

        let decrypted_message_2 = bob_restored
            .decrypt(&encrypted_message_2, alice_ad_2)
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_message_2).unwrap(),
            alice_message_2
        );

        println!("Step 12: Testing out-of-order message delivery...");
        let alice_messages = vec![
            "Message A - should be received third",
            "Message B - should be received first",
            "Message C - should be received second",
        ];
        let alice_ads = vec![b"Alice->Bob:3", b"Alice->Bob:4", b"Alice->Bob:5"];
        let mut encrypted_messages = Vec::new();

        for (i, msg) in alice_messages.iter().enumerate() {
            encrypted_messages.push(
                alice_restored
                    .encrypt(msg.as_bytes(), alice_ads[i])
                    .unwrap(),
            );
        }

        // Bob receives them out of order: B, C, A
        let decrypted_b = bob_restored
            .decrypt(&encrypted_messages[1], alice_ads[1])
            .unwrap();
        assert_eq!(String::from_utf8(decrypted_b).unwrap(), alice_messages[1]);

        let decrypted_c = bob_restored
            .decrypt(&encrypted_messages[2], alice_ads[2])
            .unwrap();
        assert_eq!(String::from_utf8(decrypted_c).unwrap(), alice_messages[2]);

        let decrypted_a = bob_restored
            .decrypt(&encrypted_messages[0], alice_ads[0])
            .unwrap();
        assert_eq!(String::from_utf8(decrypted_a).unwrap(), alice_messages[0]);

        println!("Step 13: Testing multiple DH ratchet rotations...");
        for i in 0..3 {
            // Bob to Alice
            let bob_msg = format!("Rotation test from Bob {}", i);
            let bob_ad = format!("Bob->Alice:{}", i + 2).into_bytes();
            let encrypted = bob_restored.encrypt(bob_msg.as_bytes(), &bob_ad).unwrap();
            let decrypted = alice_restored.decrypt(&encrypted, &bob_ad).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), bob_msg);

            // Alice to Bob
            let alice_msg = format!("Rotation test from Alice {}", i);
            let alice_ad = format!("Alice->Bob:{}", i + 6).into_bytes();
            let encrypted = alice_restored
                .encrypt(alice_msg.as_bytes(), &alice_ad)
                .unwrap();
            let decrypted = bob_restored.decrypt(&encrypted, &alice_ad).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), alice_msg);
        }

        println!("Step 14: Testing with different associated data...");
        let alice_message_diff_ad = "This message has different AD";
        let alice_ad_diff = b"Different-AD";
        let encrypted_diff_ad = alice_restored
            .encrypt(alice_message_diff_ad.as_bytes(), alice_ad_diff)
            .unwrap();

        // Trying to decrypt with wrong AD should fail
        let wrong_ad_result = bob_restored.decrypt(&encrypted_diff_ad, b"Wrong-AD");
        assert!(wrong_ad_result.is_err());

        // Decrypting with correct AD should work
        let correct_ad_result = bob_restored
            .decrypt(&encrypted_diff_ad, alice_ad_diff)
            .unwrap();
        assert_eq!(
            String::from_utf8(correct_ad_result).unwrap(),
            alice_message_diff_ad
        );

        println!("Step 15: Testing large message...");
        let large_message = vec![b'X'; 100 * 1024]; // 100 KB
        let large_ad = b"Large-Message";
        let encrypted_large = alice_restored.encrypt(&large_message, large_ad).unwrap();
        let decrypted_large = bob_restored.decrypt(&encrypted_large, large_ad).unwrap();
        assert_eq!(decrypted_large, large_message);

        println!("All integration tests passed successfully!");
    }

    #[test]
    fn test_multiple_sessions() {
        println!("Setting up accounts for Alice, Bob, and Charlie...");
        let alice_account = Account::new(None);
        let mut bob_account = Account::new(None);
        let mut charlie_account = Account::new(None);

        println!("Getting pre-key bundles...");
        let bob_bundle = bob_account.prekey_bundle();
        let bob_x3dh_keys = X3DHPublicKeys::from(&bob_bundle);

        let charlie_bundle = charlie_account.prekey_bundle();
        let charlie_x3dh_keys = X3DHPublicKeys::from(&charlie_bundle);

        println!("Alice creates sessions with Bob and Charlie...");
        let mut alice_bob_session = alice_account
            .create_outbound_session(&bob_x3dh_keys)
            .unwrap();
        let mut alice_charlie_session = alice_account
            .create_outbound_session(&charlie_x3dh_keys)
            .unwrap();

        println!("Bob and Charlie create inbound sessions...");
        let alice_bob_x3dh_keys = alice_bob_session.x3dh_keys().unwrap();
        let mut bob_session = bob_account
            .create_inbound_session(&alice_account.ik_public(), &alice_bob_x3dh_keys)
            .unwrap();

        let alice_charlie_x3dh_keys = alice_charlie_session.x3dh_keys().unwrap();
        let mut charlie_session = charlie_account
            .create_inbound_session(&alice_account.ik_public(), &alice_charlie_x3dh_keys)
            .unwrap();

        println!("Alice sends messages to Bob and Charlie...");
        let bob_message = "Hey Bob, it's Alice!";
        let charlie_message = "Hey Charlie, it's Alice!";

        let encrypted_bob = alice_bob_session
            .encrypt(bob_message.as_bytes(), b"Alice->Bob")
            .unwrap();
        let encrypted_charlie = alice_charlie_session
            .encrypt(charlie_message.as_bytes(), b"Alice->Charlie")
            .unwrap();

        println!("Bob and Charlie decrypt messages...");
        let decrypted_bob = bob_session.decrypt(&encrypted_bob, b"Alice->Bob").unwrap();
        let decrypted_charlie = charlie_session
            .decrypt(&encrypted_charlie, b"Alice->Charlie")
            .unwrap();

        assert_eq!(String::from_utf8(decrypted_bob).unwrap(), bob_message);
        assert_eq!(
            String::from_utf8(decrypted_charlie).unwrap(),
            charlie_message
        );

        println!("Bob and Charlie respond to Alice...");
        let bob_reply = "Hi Alice, it's Bob!";
        let charlie_reply = "Hey Alice, Charlie here!";

        let encrypted_bob_reply = bob_session
            .encrypt(bob_reply.as_bytes(), b"Bob->Alice")
            .unwrap();
        let encrypted_charlie_reply = charlie_session
            .encrypt(charlie_reply.as_bytes(), b"Charlie->Alice")
            .unwrap();

        println!("Alice decrypts responses...");
        let decrypted_bob_reply = alice_bob_session
            .decrypt(&encrypted_bob_reply, b"Bob->Alice")
            .unwrap();
        let decrypted_charlie_reply = alice_charlie_session
            .decrypt(&encrypted_charlie_reply, b"Charlie->Alice")
            .unwrap();

        assert_eq!(String::from_utf8(decrypted_bob_reply).unwrap(), bob_reply);
        assert_eq!(
            String::from_utf8(decrypted_charlie_reply).unwrap(),
            charlie_reply
        );

        println!("Testing session independence through serialization...");
        let bob_session_data = alice_bob_session.serialize().unwrap();
        let charlie_session_data = alice_charlie_session.serialize().unwrap();

        let mut alice_bob_restored = Session::deserialize(&bob_session_data).unwrap();
        let mut alice_charlie_restored = Session::deserialize(&charlie_session_data).unwrap();

        // Verify sessions work independently after restoration
        let final_bob_msg = "Final message to Bob";
        let final_charlie_msg = "Final message to Charlie";

        let encrypted_final_bob = alice_bob_restored
            .encrypt(final_bob_msg.as_bytes(), b"Alice->Bob:Final")
            .unwrap();
        let encrypted_final_charlie = alice_charlie_restored
            .encrypt(final_charlie_msg.as_bytes(), b"Alice->Charlie:Final")
            .unwrap();

        let decrypted_final_bob = bob_session
            .decrypt(&encrypted_final_bob, b"Alice->Bob:Final")
            .unwrap();
        let decrypted_final_charlie = charlie_session
            .decrypt(&encrypted_final_charlie, b"Alice->Charlie:Final")
            .unwrap();

        assert_eq!(
            String::from_utf8(decrypted_final_bob).unwrap(),
            final_bob_msg
        );
        assert_eq!(
            String::from_utf8(decrypted_final_charlie).unwrap(),
            final_charlie_msg
        );

        println!("Multiple session test passed successfully!");
    }

    #[test]
    fn test_session_resumption_after_key_loss() {
        println!("Setting up accounts for Alice and Bob...");
        let alice_account = Account::new(None);
        let mut bob_account = Account::new(None);

        println!("Establishing initial session...");
        let bob_bundle = bob_account.prekey_bundle();
        let bob_x3dh_keys = X3DHPublicKeys::from(&bob_bundle);

        let mut alice_session = alice_account
            .create_outbound_session(&bob_x3dh_keys)
            .unwrap();
        let outbound_x3dh_keys = alice_session.x3dh_keys().unwrap();
        let mut bob_session = bob_account
            .create_inbound_session(&alice_account.ik_public(), &outbound_x3dh_keys)
            .unwrap();

        println!("Exchange a few messages to advance the ratchet...");
        for i in 0..3 {
            // Alice to Bob
            let msg = format!("Message {}", i);
            let encrypted = alice_session
                .encrypt(msg.as_bytes(), b"Alice->Bob")
                .unwrap();
            let decrypted = bob_session.decrypt(&encrypted, b"Alice->Bob").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), msg);

            // Bob to Alice
            let reply = format!("Reply {}", i);
            let encrypted_reply = bob_session
                .encrypt(reply.as_bytes(), b"Bob->Alice")
                .unwrap();
            let decrypted_reply = alice_session
                .decrypt(&encrypted_reply, b"Bob->Alice")
                .unwrap();
            assert_eq!(String::from_utf8(decrypted_reply).unwrap(), reply);
        }

        println!("Simulating Bob's session loss by creating new account...");
        // Bob loses his session state and creates a new account with fresh keys
        let mut bob_new_account = Account::new(None);

        // Bob publishes new pre-key bundle
        let bob_new_bundle = bob_new_account.prekey_bundle();
        let bob_new_x3dh_keys = X3DHPublicKeys::from(&bob_new_bundle);

        println!("Alice initiates new session with Bob's new keys...");
        let mut alice_new_session = alice_account
            .create_outbound_session(&bob_new_x3dh_keys)
            .unwrap();

        let new_outbound_x3dh_keys = alice_new_session.x3dh_keys().unwrap();
        let mut bob_new_session = bob_new_account
            .create_inbound_session(&alice_account.ik_public(), &new_outbound_x3dh_keys)
            .unwrap();

        println!("Testing resumed communication...");
        let resumption_message = "Hey Bob, I'm reconnecting with you!";
        let encrypted_resumption = alice_new_session
            .encrypt(resumption_message.as_bytes(), b"Alice->Bob:New")
            .unwrap();

        let decrypted_resumption = bob_new_session
            .decrypt(&encrypted_resumption, b"Alice->Bob:New")
            .unwrap();

        assert_eq!(
            String::from_utf8(decrypted_resumption).unwrap(),
            resumption_message
        );

        let bob_welcome_back = "Welcome back, Alice!";
        let encrypted_welcome = bob_new_session
            .encrypt(bob_welcome_back.as_bytes(), b"Bob->Alice:New")
            .unwrap();

        let decrypted_welcome = alice_new_session
            .decrypt(&encrypted_welcome, b"Bob->Alice:New")
            .unwrap();

        assert_eq!(
            String::from_utf8(decrypted_welcome).unwrap(),
            bob_welcome_back
        );

        println!("Testing account serialization for persistence...");
        let alice_account_data = alice_account.serialize().unwrap();
        let bob_new_account_data = bob_new_account.serialize().unwrap();

        let alice_restored_account = Account::deserialize(&alice_account_data).unwrap();
        let bob_restored_account = Account::deserialize(&bob_new_account_data).unwrap();

        // Verify accounts work after restoration
        assert_eq!(
            alice_account.ik_public().as_bytes(),
            alice_restored_account.ik_public().as_bytes()
        );
        assert_eq!(
            bob_new_account.ik_public().as_bytes(),
            bob_restored_account.ik_public().as_bytes()
        );

        println!("Session resumption test passed successfully!");
    }

    #[test]
    fn test_concurrent_session_serialization() {
        println!("Testing concurrent session operations and serialization...");

        let alice_account = Account::new(None);
        let mut bob_account = Account::new(None);

        // Create session
        let bob_bundle = bob_account.prekey_bundle();
        let bob_x3dh_keys = X3DHPublicKeys::from(&bob_bundle);
        let alice_session = alice_account
            .create_outbound_session(&bob_x3dh_keys)
            .unwrap();

        let outbound_x3dh_keys = alice_session.x3dh_keys().unwrap();
        let bob_session = bob_account
            .create_inbound_session(&alice_account.ik_public(), &outbound_x3dh_keys)
            .unwrap();

        // Simulate mobile app pattern: serialize after every operation
        let messages = ["Message 1", "Message 2", "Message 3"];
        let mut alice_session_data = alice_session.serialize().unwrap();
        let mut bob_session_data = bob_session.serialize().unwrap();

        for (i, msg) in messages.iter().enumerate() {
            println!("Processing message {}: {}", i + 1, msg);

            // Restore Alice's session, encrypt, then serialize
            let mut alice_restored = Session::deserialize(&alice_session_data).unwrap();
            let encrypted = alice_restored.encrypt(msg.as_bytes(), b"test").unwrap();
            alice_session_data = alice_restored.serialize().unwrap();

            // Restore Bob's session, decrypt, then serialize
            let mut bob_restored = Session::deserialize(&bob_session_data).unwrap();
            let decrypted = bob_restored.decrypt(&encrypted, b"test").unwrap();
            bob_session_data = bob_restored.serialize().unwrap();

            assert_eq!(String::from_utf8(decrypted).unwrap(), *msg);
        }

        println!("Concurrent session serialization test passed successfully!");
    }

    #[test]
    fn test_account_key_rotation() {
        println!("Testing account key rotation functionality...");

        let mut alice_account = Account::new(Some(AccountConfig {
            spk_rotation_interval: Duration::from_millis(1),
            ..AccountConfig::default()
        }));

        let initial_bundle = alice_account.prekey_bundle();
        let initial_spk_id = initial_bundle.spk_public.0;

        // Wait for rotation interval to pass
        std::thread::sleep(Duration::from_millis(10));

        // Trigger key rotation
        let rotation_result = alice_account.rotate_spk();
        assert!(
            rotation_result.is_some(),
            "Key rotation should have occurred"
        );

        let (new_spk_id, _new_public_key, _signature) = rotation_result.unwrap();
        assert_ne!(initial_spk_id, new_spk_id, "SPK ID should have changed");

        // Verify new bundle has updated keys
        let new_bundle = alice_account.prekey_bundle();
        assert_eq!(new_bundle.spk_public.0, new_spk_id);

        // Test OTPK replenishment
        let replenished_keys = alice_account.replenish_otpks();
        println!("Replenished {} one-time pre-keys", replenished_keys.len());

        println!("Account key rotation test passed successfully!");
    }
}

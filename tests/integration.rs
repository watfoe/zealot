#[cfg(test)]
mod integration_tests {
    use zealot::{DoubleRatchet, IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey, X3DH};

    #[test]
    fn test_full_protocol_flow() {
        // Step 1: Generate long-term identity keys
        println!("Step 1: Generating identity keys...");
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();

        // Step 2: Bob generates pre-keys
        println!("Step 2: Bob generates pre-keys...");
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);

        // Step 3: Bob publishes his pre-key bundle
        println!("Step 3: Bob creates and publishes his pre-key bundle...");
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Step 4: Alice fetches Bob's pre-key bundle and verifies it
        println!("Step 4: Alice verifies Bob's pre-key bundle...");
        assert!(bob_bundle.verify().is_ok(), "Bundle verification failed");

        // Step 5: Alice performs X3DH with Bob's bundle
        println!("Step 5: Alice performs X3DH...");
        let x3dh = X3DH::new(b"Zealot-Integration-Test");
        let alice_x3dh_result = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();
        let alice_ephemeral_public = alice_x3dh_result.get_public_key();

        // Step 6: Alice initializes her Double Ratchet
        println!("Step 6: Alice initializes Double Ratchet...");
        let mut alice_ratchet = DoubleRatchet::initialize_as_first_sender(
            &alice_x3dh_result.get_shared_secret(),
            &bob_bundle.get_signed_pre_key_public(),
        );

        // Step 7: Alice sends an initial message to Bob
        println!("Step 7: Alice sends first message...");
        let alice_message_1 = "Hey Bob, this is a secure message!";
        let alice_ad_1 = b"Alice->Bob:1";
        let encrypted_message_1 = alice_ratchet
            .encrypt(alice_message_1.as_bytes(), alice_ad_1)
            .unwrap();

        // In a real application, Alice would send:
        // 1. Her identity public key
        // 2. Her ephemeral public key from X3DH
        // 3. The encrypted message with header

        // Step 8: Bob receives Alice's first message and processes the X3DH
        println!("Step 8: Bob processes X3DH from Alice's keys...");
        let bob_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_ephemeral_public,
            )
            .unwrap();

        // Step 9: Bob initializes his Double Ratchet with the shared secret
        println!("Step 9: Bob initializes Double Ratchet...");
        let mut bob_ratchet = DoubleRatchet::initialize_as_first_receiver(
            &bob_shared_secret,
            bob_signed_pre_key.get_key_pair(),
        );

        // Step 10: Bob decrypts Alice's first message
        println!("Step 10: Bob decrypts Alice's first message...");
        let decrypted_message_1 = bob_ratchet
            .decrypt(encrypted_message_1, alice_ad_1)
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_message_1).unwrap(),
            alice_message_1
        );

        // Step 11: Bob replies to Alice
        println!("Step 11: Bob replies to Alice...");
        let bob_message_1 = "Hi Alice! I received your secure message.";
        let bob_ad_1 = b"Bob->Alice:1";
        let encrypted_reply_1 = bob_ratchet
            .encrypt(bob_message_1.as_bytes(), bob_ad_1)
            .unwrap();

        // Step 12: Alice decrypts Bob's reply
        println!("Step 12: Alice decrypts Bob's reply...");
        let decrypted_reply_1 = alice_ratchet
            .decrypt(encrypted_reply_1, bob_ad_1)
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_reply_1).unwrap(),
            bob_message_1
        );

        // Step 13: Alice sends another message (testing ratchet advancement)
        println!("Step 13: Alice sends a second message...");
        let alice_message_2 = "How's the weather there?";
        let alice_ad_2 = b"Alice->Bob:2";
        let encrypted_message_2 = alice_ratchet
            .encrypt(alice_message_2.as_bytes(), alice_ad_2)
            .unwrap();

        // Step 14: Bob decrypts Alice's second message
        println!("Step 14: Bob decrypts Alice's second message...");
        let decrypted_message_2 = bob_ratchet
            .decrypt(encrypted_message_2, alice_ad_2)
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_message_2).unwrap(),
            alice_message_2
        );

        // Step 15: Test out-of-order message delivery
        println!("Step 15: Testing out-of-order message delivery...");
        // Alice sends 3 more messages
        let alice_messages = vec![
            "Message A - should be received third",
            "Message B - should be received first",
            "Message C - should be received second",
        ];
        let alice_ads = vec![b"Alice->Bob:3", b"Alice->Bob:4", b"Alice->Bob:5"];
        let mut encrypted_messages = Vec::new();

        for (i, msg) in alice_messages.iter().enumerate() {
            encrypted_messages.push(
                alice_ratchet
                    .encrypt(msg.as_bytes(), alice_ads[i])
                    .unwrap(),
            );
        }

        // Bob receives them out of order: B, C, A
        let decrypted_b = bob_ratchet
            .decrypt(encrypted_messages[1].clone(), alice_ads[1])
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_b).unwrap(),
            alice_messages[1]
        );

        let decrypted_c = bob_ratchet
            .decrypt(encrypted_messages[2].clone(), alice_ads[2])
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_c).unwrap(),
            alice_messages[2]
        );

        let decrypted_a = bob_ratchet
            .decrypt(encrypted_messages[0].clone(), alice_ads[0])
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_a).unwrap(),
            alice_messages[0]
        );

        // Step 16: Test multiple DH ratchet rotations
        println!("Step 16: Testing multiple DH ratchet rotations...");
        for i in 0..3 {
            // Bob to Alice
            let bob_msg = format!("Rotation test from Bob {}", i);
            let bob_ad = format!("Bob->Alice:{}", i + 2).into_bytes();
            let encrypted = bob_ratchet.encrypt(bob_msg.as_bytes(), &bob_ad).unwrap();
            let decrypted = alice_ratchet.decrypt(encrypted, &bob_ad).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), bob_msg);

            // Alice to Bob
            let alice_msg = format!("Rotation test from Alice {}", i);
            let alice_ad = format!("Alice->Bob:{}", i + 6).into_bytes();
            let encrypted = alice_ratchet.encrypt(alice_msg.as_bytes(), &alice_ad).unwrap();
            let decrypted = bob_ratchet.decrypt(encrypted, &alice_ad).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), alice_msg);
        }

        // Step 17: Test with different associated data
        println!("Step 17: Testing with different associated data...");
        let alice_message_diff_ad = "This message has different AD";
        let alice_ad_diff = b"Different-AD";
        let encrypted_diff_ad = alice_ratchet
            .encrypt(alice_message_diff_ad.as_bytes(), alice_ad_diff)
            .unwrap();

        // Trying to decrypt with wrong AD should fail
        let wrong_ad_result = bob_ratchet.decrypt(encrypted_diff_ad.clone(), b"Wrong-AD");
        assert!(wrong_ad_result.is_err());

        // Decrypting with correct AD should work
        let correct_ad_result = bob_ratchet.decrypt(encrypted_diff_ad, alice_ad_diff).unwrap();
        assert_eq!(
            String::from_utf8(correct_ad_result).unwrap(),
            alice_message_diff_ad
        );

        // Step 18: Test large message
        println!("Step 18: Testing large message...");
        let large_message = vec![b'X'; 100 * 1024]; // 100 KB
        let large_ad = b"Large-Message";
        let encrypted_large = alice_ratchet.encrypt(&large_message, large_ad).unwrap();
        let decrypted_large = bob_ratchet.decrypt(encrypted_large, large_ad).unwrap();
        assert_eq!(decrypted_large, large_message);

        println!("All integration tests passed successfully!");
    }

    #[test]
    fn test_multiple_sessions() {
        // This test simulates Alice talking to both Bob and Charlie
        println!("Setting up identity keys...");
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();
        let charlie_identity = IdentityKey::new();

        // Bob's pre-keys
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Charlie's pre-keys
        let charlie_signed_pre_key = SignedPreKey::new(1);
        let charlie_one_time_pre_key = OneTimePreKey::new(1);
        let charlie_bundle = PreKeyBundle::new(
            &charlie_identity,
            &charlie_signed_pre_key,
            Some(&charlie_one_time_pre_key),
        );

        // Alice performs X3DH with Bob
        let x3dh = X3DH::new(b"Zealot-Integration-Test");
        let alice_bob_x3dh = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();
        let alice_bob_ephemeral = alice_bob_x3dh.get_public_key();

        // Alice performs X3DH with Charlie
        let alice_charlie_x3dh = x3dh.initiate(&alice_identity, &charlie_bundle).unwrap();
        let alice_charlie_ephemeral = alice_charlie_x3dh.get_public_key();

        // Alice initializes Double Ratchet sessions
        let mut alice_bob_ratchet = DoubleRatchet::initialize_as_first_sender(
            &alice_bob_x3dh.get_shared_secret(),
            &bob_bundle.get_signed_pre_key_public(),
        );

        let mut alice_charlie_ratchet = DoubleRatchet::initialize_as_first_sender(
            &alice_charlie_x3dh.get_shared_secret(),
            &charlie_bundle.get_signed_pre_key_public(),
        );

        // Bob and Charlie process X3DH
        let bob_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_bob_ephemeral,
            )
            .unwrap();

        let charlie_shared_secret = x3dh
            .process_initiation(
                &charlie_identity,
                &charlie_signed_pre_key,
                Some(charlie_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_charlie_ephemeral,
            )
            .unwrap();

        // Bob and Charlie initialize Double Ratchet sessions
        let mut bob_ratchet = DoubleRatchet::initialize_as_first_receiver(
            &bob_shared_secret,
            bob_signed_pre_key.get_key_pair(),
        );

        let mut charlie_ratchet = DoubleRatchet::initialize_as_first_receiver(
            &charlie_shared_secret,
            charlie_signed_pre_key.get_key_pair(),
        );

        // Alice sends messages to Bob and Charlie
        let bob_message = "Hey Bob, it's Alice!";
        let charlie_message = "Hey Charlie, it's Alice!";

        let encrypted_bob = alice_bob_ratchet
            .encrypt(bob_message.as_bytes(), b"Alice->Bob")
            .unwrap();
        let encrypted_charlie = alice_charlie_ratchet
            .encrypt(charlie_message.as_bytes(), b"Alice->Charlie")
            .unwrap();

        // Bob and Charlie decrypt messages
        let decrypted_bob = bob_ratchet
            .decrypt(encrypted_bob, b"Alice->Bob")
            .unwrap();
        let decrypted_charlie = charlie_ratchet
            .decrypt(encrypted_charlie, b"Alice->Charlie")
            .unwrap();

        assert_eq!(String::from_utf8(decrypted_bob).unwrap(), bob_message);
        assert_eq!(
            String::from_utf8(decrypted_charlie).unwrap(),
            charlie_message
        );

        // Bob and Charlie respond to Alice
        let bob_reply = "Hi Alice, it's Bob!";
        let charlie_reply = "Hey Alice, Charlie here!";

        let encrypted_bob_reply = bob_ratchet
            .encrypt(bob_reply.as_bytes(), b"Bob->Alice")
            .unwrap();
        let encrypted_charlie_reply = charlie_ratchet
            .encrypt(charlie_reply.as_bytes(), b"Charlie->Alice")
            .unwrap();

        // Alice decrypts responses
        let decrypted_bob_reply = alice_bob_ratchet
            .decrypt(encrypted_bob_reply, b"Bob->Alice")
            .unwrap();
        let decrypted_charlie_reply = alice_charlie_ratchet
            .decrypt(encrypted_charlie_reply, b"Charlie->Alice")
            .unwrap();

        assert_eq!(
            String::from_utf8(decrypted_bob_reply).unwrap(),
            bob_reply
        );
        assert_eq!(
            String::from_utf8(decrypted_charlie_reply).unwrap(),
            charlie_reply
        );

        println!("Multiple session test passed successfully!");
    }

    #[test]
    fn test_session_resumption_after_key_loss() {
        // This test simulates what happens when a user loses their session and has to rebuild it
        println!("Setting up identity keys...");
        let alice_identity = IdentityKey::new();
        let bob_identity = IdentityKey::new();

        // Bob's pre-keys
        let bob_signed_pre_key = SignedPreKey::new(1);
        let bob_one_time_pre_key = OneTimePreKey::new(1);
        let bob_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time_pre_key),
        );

        // Alice performs X3DH with Bob
        let x3dh = X3DH::new(b"Zealot-Integration-Test");
        let alice_bob_x3dh = x3dh.initiate(&alice_identity, &bob_bundle).unwrap();
        let alice_bob_ephemeral = alice_bob_x3dh.get_public_key();

        // Alice initializes Double Ratchet session
        let mut alice_ratchet = DoubleRatchet::initialize_as_first_sender(
            &alice_bob_x3dh.get_shared_secret(),
            &bob_bundle.get_signed_pre_key_public(),
        );

        // Bob processes X3DH
        let bob_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_signed_pre_key,
                Some(bob_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_bob_ephemeral,
            )
            .unwrap();

        // Bob initializes Double Ratchet session
        let mut bob_ratchet = DoubleRatchet::initialize_as_first_receiver(
            &bob_shared_secret,
            bob_signed_pre_key.get_key_pair(),
        );

        // Exchange a few messages to advance the ratchet
        for i in 0..3 {
            // Alice to Bob
            let msg = format!("Message {}", i);
            let encrypted = alice_ratchet.encrypt(msg.as_bytes(), b"Alice->Bob").unwrap();
            let decrypted = bob_ratchet.decrypt(encrypted, b"Alice->Bob").unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), msg);

            // Bob to Alice
            let reply = format!("Reply {}", i);
            let encrypted_reply = bob_ratchet.encrypt(reply.as_bytes(), b"Bob->Alice").unwrap();
            let decrypted_reply = alice_ratchet.decrypt(encrypted_reply, b"Bob->Alice").unwrap();
            assert_eq!(String::from_utf8(decrypted_reply).unwrap(), reply);
        }

        // Now simulate Bob losing his session state
        // In a real application, he would need to:
        // 1. Generate new pre-keys
        // 2. Publish a new bundle
        // 3. Signal to Alice somehow that he needs to re-initialize

        println!("Simulating Bob's session loss...");
        let bob_new_signed_pre_key = SignedPreKey::new(2);
        let bob_new_one_time_pre_key = OneTimePreKey::new(2);

        let bob_new_bundle = PreKeyBundle::new(
            &bob_identity,
            &bob_new_signed_pre_key,
            Some(&bob_new_one_time_pre_key),
        );

        // Alice initiates a new X3DH with Bob's new bundle
        let alice_new_x3dh = x3dh.initiate(&alice_identity, &bob_new_bundle).unwrap();
        let alice_new_ephemeral = alice_new_x3dh.get_public_key();

        // Alice creates a new ratchet session
        let mut alice_new_ratchet = DoubleRatchet::initialize_as_first_sender(
            &alice_new_x3dh.get_shared_secret(),
            &bob_new_bundle.get_signed_pre_key_public(),
        );

        // Bob processes the new X3DH
        let bob_new_shared_secret = x3dh
            .process_initiation(
                &bob_identity,
                &bob_new_signed_pre_key,
                Some(bob_new_one_time_pre_key),
                &alice_identity.get_public_dh_key(),
                &alice_new_ephemeral,
            )
            .unwrap();

        // Bob initializes a new ratchet session
        let mut bob_new_ratchet = DoubleRatchet::initialize_as_first_receiver(
            &bob_new_shared_secret,
            bob_new_signed_pre_key.get_key_pair(),
        );

        // Test that they can continue communicating
        let resumption_message = "Hey Bob, I'm reconnecting with you!";
        let encrypted_resumption = alice_new_ratchet
            .encrypt(resumption_message.as_bytes(), b"Alice->Bob:New")
            .unwrap();

        let decrypted_resumption = bob_new_ratchet
            .decrypt(encrypted_resumption, b"Alice->Bob:New")
            .unwrap();

        assert_eq!(
            String::from_utf8(decrypted_resumption).unwrap(),
            resumption_message
        );

        // Bob responds
        let bob_welcome_back = "Welcome back, Alice!";
        let encrypted_welcome = bob_new_ratchet
            .encrypt(bob_welcome_back.as_bytes(), b"Bob->Alice:New")
            .unwrap();

        let decrypted_welcome = alice_new_ratchet
            .decrypt(encrypted_welcome, b"Bob->Alice:New")
            .unwrap();

        assert_eq!(
            String::from_utf8(decrypted_welcome).unwrap(),
            bob_welcome_back
        );

        println!("Session resumption test passed successfully!");
    }
}

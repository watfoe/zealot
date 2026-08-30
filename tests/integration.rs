#[cfg(test)]
mod integration_tests {
    use std::time::Duration;
    use zealot::{Account, AccountConfig, Session, X3DHPublicKeys};

    /// Stands in for the server: publishes `account`'s pre-key bundle and returns
    /// what a peer fetching it would receive - the identity and signed pre-key,
    /// plus exactly one of the advertised one-time pre-keys. Allocating a single
    /// one-time pre-key per fetch is the server's job, which is why this lives in
    /// the test harness rather than in the crate.
    fn create_test_pkb(account: &Account) -> X3DHPublicKeys {
        let pkb = account.prekey_bundle();
        let otpk = pkb
            .otpks_public
            .iter()
            .next()
            .map(|(id, key)| (*id, key.to_bytes()));
        X3DHPublicKeys::try_from(
            pkb.ik_public.to_bytes(),
            pkb.signing_key_public.to_bytes(),
            (pkb.spk_public.0, pkb.spk_public.1.to_bytes()),
            pkb.signature.to_bytes(),
            otpk,
        )
        .unwrap()
    }

    #[test]
    fn test_full_protocol_lifecycle() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        let b_pkb = create_test_pkb(&b_acc);
        assert!(b_pkb.verify().is_ok(), "bundle verification failed");

        let mut a_ses = a_acc.create_outbound_session(&b_pkb).unwrap();

        let outbound_x3dh_keys = a_ses.x3dh_keys().unwrap();
        let mut b_ses = b_acc
            .create_inbound_session(a_acc.ik_public(), &outbound_x3dh_keys)
            .unwrap();

        let a_msg_1 = "Hey Bob, this is a secure message!";
        let ciphertext_1 = a_ses.encrypt(a_msg_1.as_bytes()).unwrap();
        let plaintext_1 = b_ses.decrypt(&ciphertext_1).unwrap();
        assert_eq!(String::from_utf8(plaintext_1).unwrap(), a_msg_1);

        let b_msg_1 = "Hi Alice! I received your secure message.";
        let ciphertext_2 = b_ses.encrypt(b_msg_1.as_bytes()).unwrap();
        let plaintext_2 = a_ses.decrypt(&ciphertext_2).unwrap();
        assert_eq!(String::from_utf8(plaintext_2).unwrap(), b_msg_1);

        let a_ser_ses = a_ses.serialize().unwrap();
        let b_ser_ses = b_ses.serialize().unwrap();

        let mut a_unser_ses = Session::deserialize(&a_ser_ses).unwrap();
        let mut b_unser_ses = Session::deserialize(&b_ser_ses).unwrap();

        let a_msg_2 = "How's the weather there?";
        let ciphertext_3 = a_unser_ses.encrypt(a_msg_2.as_bytes()).unwrap();
        let plaintext_3 = b_unser_ses.decrypt(&ciphertext_3).unwrap();
        assert_eq!(String::from_utf8(plaintext_3).unwrap(), a_msg_2);

        let a_msgs = vec![
            "Message A - third",
            "Message B - first",
            "Message C - second",
        ];
        let mut ciphertexts = Vec::new();
        for msg in a_msgs.iter() {
            ciphertexts.push(a_unser_ses.encrypt(msg.as_bytes()).unwrap());
        }

        // Bob receives them out of order: B, C, A
        let plaintext_b = b_unser_ses.decrypt(&ciphertexts[1]).unwrap();
        assert_eq!(String::from_utf8(plaintext_b).unwrap(), a_msgs[1]);

        let plaintext_c = b_unser_ses.decrypt(&ciphertexts[2]).unwrap();
        assert_eq!(String::from_utf8(plaintext_c).unwrap(), a_msgs[2]);

        let plaintext_a = b_unser_ses.decrypt(&ciphertexts[0]).unwrap();
        assert_eq!(String::from_utf8(plaintext_a).unwrap(), a_msgs[0]);

        for i in 0..3 {
            // Bob to Alice
            let b_msg = format!("Rotation test from Bob {i}");
            let ciphertext = b_unser_ses.encrypt(b_msg.as_bytes()).unwrap();
            let plaintext = a_unser_ses.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), b_msg);

            // Alice to Bob
            let a_msg = format!("Rotation test from Alice {i}");
            let ciphertext = a_unser_ses.encrypt(a_msg.as_bytes()).unwrap();
            let plaintext = b_unser_ses.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), a_msg);
        }

        let msg = vec![b'X'; 100 * 1024]; // 100 KB
        let ciphertext = a_unser_ses.encrypt(&msg).unwrap();
        let plaintext = b_unser_ses.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_multiple_sessions() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);
        let mut c_acc = Account::new(None);

        let b_pkb = create_test_pkb(&b_acc);
        let c_pkb = create_test_pkb(&c_acc);

        let mut a_b_out_ses = a_acc.create_outbound_session(&b_pkb).unwrap();
        let mut a_c_out_ses = a_acc.create_outbound_session(&c_pkb).unwrap();

        let a_b_x3dh_keys = a_b_out_ses.x3dh_keys().unwrap();
        let mut a_b_in_ses = b_acc
            .create_inbound_session(a_acc.ik_public(), &a_b_x3dh_keys)
            .unwrap();

        let a_c_x3dh_keys = a_c_out_ses.x3dh_keys().unwrap();
        let mut a_c_in_ses = c_acc
            .create_inbound_session(a_acc.ik_public(), &a_c_x3dh_keys)
            .unwrap();

        let a_b_msg = "Hey Bob, it's Alice!";
        let a_c_msg = "Hey Charlie, it's Alice!";

        let a_b_ciphertext = a_b_out_ses.encrypt(a_b_msg.as_bytes()).unwrap();
        let a_c_ciphertext = a_c_out_ses.encrypt(a_c_msg.as_bytes()).unwrap();

        let a_b_plaintext = a_b_in_ses.decrypt(&a_b_ciphertext).unwrap();
        let a_c_plaintext = a_c_in_ses.decrypt(&a_c_ciphertext).unwrap();

        assert_eq!(String::from_utf8(a_b_plaintext).unwrap(), a_b_msg);
        assert_eq!(String::from_utf8(a_c_plaintext).unwrap(), a_c_msg);

        let b_a_msg = "Hi Alice, it's Bob!";
        let c_a_msg = "Hey Alice, Charlie here!";

        let b_a_ciphertext = a_b_in_ses.encrypt(b_a_msg.as_bytes()).unwrap();
        let c_a_ciphertext = a_c_in_ses.encrypt(c_a_msg.as_bytes()).unwrap();

        let b_a_plaintext = a_b_out_ses.decrypt(&b_a_ciphertext).unwrap();
        let c_a_plaintext = a_c_out_ses.decrypt(&c_a_ciphertext).unwrap();

        assert_eq!(String::from_utf8(b_a_plaintext).unwrap(), b_a_msg);
        assert_eq!(String::from_utf8(c_a_plaintext).unwrap(), c_a_msg);

        let a_b_ser_ses = a_b_out_ses.serialize().unwrap();
        let a_c_ser_ses = a_c_out_ses.serialize().unwrap();

        let mut a_b_unser_ses = Session::deserialize(&a_b_ser_ses).unwrap();
        let mut a_c_unser_ses = Session::deserialize(&a_c_ser_ses).unwrap();

        // Verify sessions work independently after restoration
        let a_b_msg_2 = "New message to Bob";
        let a_c_msg_2 = "New message to Charlie";

        let a_b_ciphertext_2 = a_b_unser_ses.encrypt(a_b_msg_2.as_bytes()).unwrap();
        let a_c_ciphertext_2 = a_c_unser_ses.encrypt(a_c_msg_2.as_bytes()).unwrap();

        let a_b_plaintext_2 = a_b_in_ses.decrypt(&a_b_ciphertext_2).unwrap();
        let a_c_plaintext_2 = a_c_in_ses.decrypt(&a_c_ciphertext_2).unwrap();

        assert_eq!(String::from_utf8(a_b_plaintext_2).unwrap(), a_b_msg_2);
        assert_eq!(String::from_utf8(a_c_plaintext_2).unwrap(), a_c_msg_2);
    }

    #[test]
    fn test_session_resumption_after_key_loss() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        let b_x3dh_keys = create_test_pkb(&b_acc);

        let mut a_ses = a_acc.create_outbound_session(&b_x3dh_keys).unwrap();
        let outbound_x3dh_keys = a_ses.x3dh_keys().unwrap();
        let mut b_ses = b_acc
            .create_inbound_session(a_acc.ik_public(), &outbound_x3dh_keys)
            .unwrap();

        for i in 0..3 {
            // Alice to Bob
            let msg = format!("Message {i}");
            let ciphertext = a_ses.encrypt(msg.as_bytes()).unwrap();
            let plaintext = b_ses.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), msg);

            // Bob to Alice
            let msg = format!("Reply {i}");
            let ciphertext = b_ses.encrypt(msg.as_bytes()).unwrap();
            let plaintext = a_ses.decrypt(&ciphertext).unwrap();
            assert_eq!(String::from_utf8(plaintext).unwrap(), msg);
        }

        // Bob loses his session state and creates a new account with fresh keys
        let mut b_new_acc = Account::new(None);

        // Bob publishes new pre-key bundle
        let b_new_x3dh_keys = create_test_pkb(&b_new_acc);

        let mut a_new_ses = a_acc.create_outbound_session(&b_new_x3dh_keys).unwrap();

        let new_outbound_x3dh_keys = a_new_ses.x3dh_keys().unwrap();
        let mut b_new_ses = b_new_acc
            .create_inbound_session(a_acc.ik_public(), &new_outbound_x3dh_keys)
            .unwrap();

        let a_msg_2 = "Hey Bob, reconnecting with you!";
        let a_ciphertext_2 = a_new_ses.encrypt(a_msg_2.as_bytes()).unwrap();
        let a_plaintext_2 = b_new_ses.decrypt(&a_ciphertext_2).unwrap();

        assert_eq!(String::from_utf8(a_plaintext_2).unwrap(), a_msg_2);

        let b_msg_2 = "Welcome back, Alice!";
        let b_ciphertext_2 = b_new_ses.encrypt(b_msg_2.as_bytes()).unwrap();
        let b_plaintext_2 = a_new_ses.decrypt(&b_ciphertext_2).unwrap();

        assert_eq!(String::from_utf8(b_plaintext_2).unwrap(), b_msg_2);

        let a_ser_acc = a_acc.serialize().unwrap();
        let b_ser_acc = b_new_acc.serialize().unwrap();

        let a_unser_acc = Account::deserialize(&a_ser_acc).unwrap();
        let b_unser_acc = Account::deserialize(&b_ser_acc).unwrap();

        // Verify accounts work after restoration
        assert_eq!(
            a_acc.ik_public().as_bytes(),
            a_unser_acc.ik_public().as_bytes()
        );
        assert_eq!(
            b_new_acc.ik_public().as_bytes(),
            b_unser_acc.ik_public().as_bytes()
        );
    }

    #[test]
    fn test_concurrent_session_serialization() {
        let a_acc = Account::new(None);
        let mut b_acc = Account::new(None);

        // Create session
        let b_x3dh_keys = create_test_pkb(&b_acc);
        let a_ses = a_acc.create_outbound_session(&b_x3dh_keys).unwrap();

        let outbound_x3dh_keys = a_ses.x3dh_keys().unwrap();
        let b_ses = b_acc
            .create_inbound_session(a_acc.ik_public(), &outbound_x3dh_keys)
            .unwrap();

        // Simulate mobile app pattern: serialize after every operation
        let msgs = ["Message 1", "Message 2", "Message 3"];
        let mut a_ser_ses = a_ses.serialize().unwrap();
        let mut b_ser_ses = b_ses.serialize().unwrap();

        for msg in msgs.iter() {
            // Restore Alice's session, encrypt, then serialize
            let mut a_unser_ses = Session::deserialize(&a_ser_ses).unwrap();
            let ciphertext = a_unser_ses.encrypt(msg.as_bytes()).unwrap();
            a_ser_ses = a_unser_ses.serialize().unwrap();

            // Restore Bob's session, decrypt, then serialize
            let mut b_unser_ses = Session::deserialize(&b_ser_ses).unwrap();
            let plaintext = b_unser_ses.decrypt(&ciphertext).unwrap();
            b_ser_ses = b_unser_ses.serialize().unwrap();

            assert_eq!(String::from_utf8(plaintext).unwrap(), *msg);
        }
    }

    #[test]
    fn test_account_key_rotation() {
        let mut a_acc = Account::new(Some(AccountConfig {
            spk_rotation_interval: Duration::from_millis(1),
            ..AccountConfig::default()
        }));

        let pkb = a_acc.prekey_bundle();
        let spk_id = pkb.spk_public.0;

        // Wait for rotation interval to pass
        std::thread::sleep(Duration::from_millis(10));

        // Trigger key rotation
        let rotation_result = a_acc.rotate_spk();
        assert!(
            rotation_result.is_some(),
            "key rotation should have occurred"
        );

        let (new_spk_id, _new_pkb, _signature) = rotation_result.unwrap();
        assert_ne!(spk_id, new_spk_id, "spk id should have changed");

        // Verify new bundle has updated keys
        let new_pkb = a_acc.prekey_bundle();
        assert_eq!(new_pkb.spk_public.0, new_spk_id);

        // Test OTPK replenishment
        let replenished_keys = a_acc.replenish_otpks();
        println!("Replenished {} one-time pre-keys", replenished_keys.len());
    }
}

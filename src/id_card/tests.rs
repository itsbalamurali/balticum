#[cfg(test)]
mod tests {
    use crate::id_card::{IDCardClient, IDCardError}; // Added IDCardError

    #[test]
    fn test_id_card_client_new_non_existent_module() {
        let result = IDCardClient::new("/path/to/non/existent/module.so");
        assert!(result.is_err());
        match result.err().unwrap() {
            IDCardError::ModuleInitializationFailed(_) => {
                // Expected error
            }
            _ => panic!("Expected ModuleInitializationFailed error"),
        }
    }

    #[test]
    fn test_id_card_client_new_empty_path() {
        // Test with an empty path, which should also fail initialization.
        let result = IDCardClient::new("");
        assert!(result.is_err());
        match result.err().unwrap() {
            IDCardError::ModuleInitializationFailed(_) => {
                // Expected error
            }
            _ => panic!("Expected ModuleInitializationFailed for empty path"),
        }
    }

    #[test]
    #[ignore] // Requires a real PKCS#11 module (e.g., SoftHSM2) and setup
    fn test_open_close_session() {
        // Placeholder for actual test logic with a configured PKCS#11 module
        // Example steps:
        // 1. Get PKCS#11 module path from environment or config.
        // 2. client = IDCardClient::new(&path).unwrap();
        // 3. slots = client.list_slots().unwrap();
        // 4. Assume first slot with a token is found: slot_id = slots[0].id;
        // 5. session = client.open_session(slot_id, true).unwrap(); // R/W session
        // 6. client.close_session(session).unwrap();
        assert!(true, "Test needs a real PKCS#11 setup to run.");
    }

    #[test]
    #[ignore] // Requires a real PKCS#11 module and a token with a known PIN
    fn test_login_logout() {
        // Placeholder for actual test logic
        // Example steps:
        // 1. Setup as in test_open_close_session.
        // 2. session = client.open_session(slot_id, true).unwrap();
        // 3. client.login(session, "USER_PIN_HERE").unwrap(); // Use actual PIN
        // 4. client.logout(session).unwrap();
        // 5. client.close_session(session).unwrap();
        assert!(true, "Test needs a real PKCS#11 setup and PIN to run.");
    }

    #[test]
    #[ignore] // Requires a real PKCS#11 module and a token with a known PIN
    fn test_login_incorrect_pin() {
        // Placeholder for actual test logic
        // Example steps:
        // 1. Setup.
        // 2. session = client.open_session(slot_id, true).unwrap();
        // 3. result = client.login(session, "WRONG_PIN");
        // 4. assert!(result.is_err());
        // 5. assert!(matches!(result.err().unwrap(), IDCardError::PinIncorrect));
        // 6. client.close_session(session).unwrap(); // Ensure session is closed
        assert!(true, "Test needs a real PKCS#11 setup and PIN to run.");
    }

    #[test]
    #[ignore] // Requires a real PKCS#11 module and a token with objects
    fn test_find_certificates() {
        // Placeholder for actual test logic
        // Example steps:
        // 1. Setup client and login as in test_login_logout.
        // 2. certificates = client.find_certificates(session).unwrap();
        // 3. Assert based on expected certificates on the token.
        //    e.g., assert!(!certificates.is_empty());
        //    e.g., for cert in certificates { println!("Cert Label: {}, Subject: {:?}", cert.label, String::from_utf8_lossy(&cert.subject)); }
        // 4. client.logout(session).unwrap();
        // 5. client.close_session(session).unwrap();
        assert!(true, "Test needs a real PKCS#11 setup with certificates to run.");
    }

    #[test]
    #[ignore] // Requires a real PKCS#11 module and a token with objects
    fn test_find_private_keys() {
        // Placeholder for actual test logic
        // Example steps:
        // 1. Setup client and login.
        // 2. private_keys = client.find_private_keys(session, None).unwrap(); // Find all private keys
        // 3. Assert based on expected private keys on the token.
        //    e.g., assert!(!private_keys.is_empty());
        //    e.g., for key in private_keys { println!("Key Label: {}, ID: {:?}", key.label, key.id); }
        // 4. client.logout(session).unwrap();
        // 5. client.close_session(session).unwrap();
        assert!(true, "Test needs a real PKCS#11 setup with private keys to run.");
    }
}

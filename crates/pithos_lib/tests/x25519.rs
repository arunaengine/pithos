#[cfg(test)]
mod tests {
    use pithos_lib::helpers::x25519_keys::*;
    use x25519_dalek::PublicKey;

    #[test]
    fn test_generate_private_key() {
        let key = generate_private_key().expect("Failed to generate private key");
        // Verify we can derive a public key
        let _public_key = PublicKey::from(&key);
    }

    #[test]
    fn test_derive_shared_key() {
        let private_a = generate_private_key().unwrap();
        let public_a = PublicKey::from(&private_a);
        let private_b = generate_private_key().unwrap();
        let public_b = PublicKey::from(&private_b);

        let shared_ab = derive_shared_key(&private_a, &public_b);
        let shared_ba = derive_shared_key(&private_b, &public_a);

        // The shared secrets should be equal
        assert_eq!(shared_ab, shared_ba);

        // The shared secret should be 32 bytes
        assert_eq!(shared_ab.len(), 32);
    }

    #[test]
    fn test_private_key_round_trip() {
        let original_key = generate_private_key().expect("Failed to generate key");

        // Convert to PEM
        let pem_bytes = private_key_to_pem_bytes(&original_key).expect("Failed to convert to PEM");

        // Parse back from PEM
        let parsed_key = private_key_from_pem_bytes(&pem_bytes).expect("Failed to parse from PEM");

        // Verify keys are equivalent by comparing derived public keys
        let original_public = PublicKey::from(&original_key);
        let parsed_public = PublicKey::from(&parsed_key);

        assert_eq!(original_public.as_bytes(), parsed_public.as_bytes());
    }

    #[test]
    fn test_public_key_round_trip() {
        let private_key = generate_private_key().expect("Failed to generate key");
        let original_public = PublicKey::from(&private_key);

        // Convert to PEM
        let pem_bytes =
            public_key_to_pem_bytes(&original_public).expect("Failed to convert to PEM");

        // Parse back from PEM
        let parsed_public =
            public_key_from_pem_bytes(&pem_bytes).expect("Failed to parse from PEM");

        assert_eq!(original_public.as_bytes(), parsed_public.as_bytes());
    }

    #[test]
    fn test_pem_format_validation() {
        let private_key = generate_private_key().expect("Failed to generate key");
        let pem_bytes = private_key_to_pem_bytes(&private_key).expect("Failed to convert");
        let pem_str = String::from_utf8(pem_bytes).expect("Invalid UTF-8");

        assert!(pem_str.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem_str.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_public_pem_format_validation() {
        let private_key = generate_private_key().expect("Failed to generate key");
        let public_key = PublicKey::from(&private_key);
        let pem_bytes = public_key_to_pem_bytes(&public_key).expect("Failed to convert");
        let pem_str = String::from_utf8(pem_bytes).expect("Invalid UTF-8");

        assert!(pem_str.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem_str.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_invalid_pem_format() {
        let invalid_pem = b"this is not valid PEM data";
        let result = private_key_from_pem_bytes(invalid_pem);
        assert!(result.is_err());

        let result = public_key_from_pem_bytes(invalid_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_utf8() {
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let result = private_key_from_pem_bytes(&invalid_utf8);
        assert!(matches!(result, Err(CryptError::InvalidPemFormat(_))));
    }

    #[test]
    fn test_multiple_key_generation_uniqueness() {
        let key1 = generate_private_key().expect("Failed to generate key1");
        let key2 = generate_private_key().expect("Failed to generate key2");

        let public1 = PublicKey::from(&key1);
        let public2 = PublicKey::from(&key2);

        // Keys should be different
        assert_ne!(public1.as_bytes(), public2.as_bytes());
    }

    #[test]
    fn test_error_display() {
        let error = CryptError::InvalidPemFormat("test message".to_string());
        assert_eq!(format!("{error}"), "Invalid PEM format: test message");

        let error = CryptError::KeyGenerationError("generation failed".to_string());
        assert_eq!(
            format!("{error}"),
            "Key generation error: generation failed"
        );
    }

    // Property-based testing
    #[test]
    fn test_many_round_trips() {
        for _ in 0..100 {
            let private_key = generate_private_key().expect("Failed to generate key");
            let public_key = PublicKey::from(&private_key);

            // Test private key round trip
            let private_pem =
                private_key_to_pem_bytes(&private_key).expect("Failed to encode private key");

            let parsed_private =
                private_key_from_pem_bytes(&private_pem).expect("Failed to parse private key");
            let parsed_public_from_private = PublicKey::from(&parsed_private);

            // Test public key round trip
            let public_pem =
                public_key_to_pem_bytes(&public_key).expect("Failed to encode public key");
            let parsed_public =
                public_key_from_pem_bytes(&public_pem).expect("Failed to parse public key");

            assert_eq!(public_key.as_bytes(), parsed_public_from_private.as_bytes());
            assert_eq!(public_key.as_bytes(), parsed_public.as_bytes());
        }
    }
}

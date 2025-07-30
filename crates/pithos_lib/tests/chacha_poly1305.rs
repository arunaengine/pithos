#[cfg(test)]
mod tests {
    use pithos_lib::helpers::chacha_poly1305::*;

    #[test]
    fn test_encrypt_and_decrypt_chunk_roundtrip() {
        let key = [42u8; 32];
        let msg = b"hello world";
        let aad = b"";

        let encrypted = encrypt_chunk(msg, aad, &key).expect("encryption failed");
        let decrypted = decrypt_chunk(&encrypted, &key).expect("decryption failed");

        // The decrypted message should match the original
        assert_eq!(&decrypted[..msg.len()], msg);
    }

    #[test]
    fn test_decrypt_chunk_too_small() {
        let key = [42u8; 32];
        let chunk = [1u8; 10]; // less than 15 bytes

        let result = decrypt_chunk(&chunk, &key);
        assert!(matches!(result, Err(ChaChaPoly1305Error::ChunkTooSmall(_))));
    }

    #[test]
    fn test_decrypt_chunk_invalid_nonce() {
        let key = [42u8; 32];
        let chunk = [1u8; 20];
        // Make nonce slice not 12 bytes
        let result = decrypt_chunk(&chunk[..5], &key);
        assert!(
            matches!(result, Err(ChaChaPoly1305Error::ChunkTooSmall(_)))
                || matches!(result, Err(ChaChaPoly1305Error::InvalidNonce(_)))
        );
    }

    #[test]
    fn test_encrypt_chunk_invalid_key() {
        let msg = b"hello";
        let aad = b"";
        let bad_key = [1u8; 10]; // too short

        let result = encrypt_chunk(msg, aad, &bad_key);
        assert!(matches!(
            result,
            Err(ChaChaPoly1305Error::CipherInitError(_))
        ));
    }
}

use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305,
};
use digest::KeyInit;
use rand_core::OsRng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChaChaPoly1305Error {
    #[error("Message too large: {0}")]
    MessageTooLarge(usize),
    #[error("Unable to initialize cipher from key: {0}")]
    CipherInitError(String),
    #[error("Unable to encrypt chunk: {0}")]
    EncryptionError(String),
    #[error("Unable to decrypt chunk: {0}")]
    DecryptionError(String),
    #[error("Invalid nonce size: {0}")]
    InvalidNonce(usize),
    #[error("Unexpected chunk size < 15: {0}")]
    ChunkTooSmall(usize),
}

pub fn encrypt_chunk(msg: &[u8], aad: &[u8], enc: &[u8]) -> Result<Bytes, ChaChaPoly1305Error> {
    let mut nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut bytes = BytesMut::new();
    let pload = Payload { msg, aad };
    let cipher = ChaCha20Poly1305::new_from_slice(enc)
        .map_err(|e| ChaChaPoly1305Error::CipherInitError(e.to_string()))?;
    let mut result = cipher
        .encrypt(&nonce, pload)
        .map_err(|e| ChaChaPoly1305Error::EncryptionError(e.to_string()))?;

    while result.ends_with(&[0u8]) {
        let pload = Payload { msg, aad };
        nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        result = cipher
            .encrypt(&nonce, pload)
            .map_err(|e| ChaChaPoly1305Error::EncryptionError(e.to_string()))?;
    }

    bytes.put(nonce.as_ref());
    bytes.put(result.as_ref());
    bytes.put(aad);

    Ok(bytes.freeze())
}

pub fn decrypt_chunk(
    chunk: &[u8],
    decryption_key: &[u8; 32],
) -> Result<Vec<u8>, ChaChaPoly1305Error> {
    if chunk.len() < 15 {
        return Err(ChaChaPoly1305Error::ChunkTooSmall(chunk.len()));
    }

    let (nonce_slice, data) = chunk.split_at(12);

    if nonce_slice.len() != 12 {
        return Err(ChaChaPoly1305Error::InvalidNonce(nonce_slice.len()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| ChaChaPoly1305Error::CipherInitError(e.to_string()))?;

    let payload = Payload {
        msg: data,
        aad: b"",
    };

    cipher
        .decrypt(nonce_slice.into(), payload)
        .map(|plaintext| plaintext.into())
        .map_err(|e| ChaChaPoly1305Error::DecryptionError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let chunk = vec![1u8; 20];
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

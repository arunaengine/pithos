use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Generate, Payload},
};
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

#[tracing::instrument(level = "trace", skip(msg, aad, enc))]
pub fn encrypt_chunk(msg: &[u8], aad: &[u8], enc: &[u8]) -> Result<Vec<u8>, ChaChaPoly1305Error> {
    let nonce = Nonce::generate();
    let payload = Payload { msg, aad };
    let cipher = ChaCha20Poly1305::new_from_slice(enc)
        .map_err(|e| ChaChaPoly1305Error::CipherInitError(e.to_string()))?;

    // Encrypt chunk
    let result = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| ChaChaPoly1305Error::EncryptionError(e.to_string()))?;

    // Gather nonce, encrypted chunk and aad together
    let mut bytes = Vec::new();
    bytes.extend(nonce.as_slice());
    bytes.extend(result.as_slice());
    bytes.extend(aad);

    Ok(bytes)
}

#[tracing::instrument(level = "trace", skip(chunk, decryption_key))]
pub fn decrypt_chunk(
    chunk: &[u8],
    decryption_key: &[u8; 32],
) -> Result<Vec<u8>, ChaChaPoly1305Error> {
    if chunk.len() < 15 {
        return Err(ChaChaPoly1305Error::ChunkTooSmall(chunk.len()));
    }

    let (nonce_slice, data) = chunk.split_at(12);

    let nonce = <&Nonce>::try_from(nonce_slice)
        .map_err(|_| ChaChaPoly1305Error::InvalidNonce(nonce_slice.len()))?;

    let cipher = ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| ChaChaPoly1305Error::CipherInitError(e.to_string()))?;

    let payload = Payload {
        msg: data,
        aad: b"",
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| ChaChaPoly1305Error::DecryptionError(e.to_string()))
}

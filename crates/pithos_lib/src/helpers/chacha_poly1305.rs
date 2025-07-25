use byteorder::{BigEndian, ByteOrder};
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
) -> Result<Bytes, ChaChaPoly1305Error> {
    if chunk.len() < 15 {
        return Err(ChaChaPoly1305Error::ChunkTooSmall(chunk.len()));
    }

    let (nonce_slice, data) = chunk.split_at(12);

    if nonce_slice.len() != 12 {
        return Err(ChaChaPoly1305Error::InvalidNonce(nonce_slice.len()));
    }

    let last_4 = {
        let (l1, rem) = data.split_last().unwrap_or((&0u8, &[0u8]));
        let (l2, rem) = rem.split_last().unwrap_or((&0u8, &[0u8]));
        let (l3, rem) = rem.split_last().unwrap_or((&0u8, &[0u8]));
        let (l4, _) = rem.split_last().unwrap_or((&0u8, &[0u8]));
        (l4, l3, l2, l1)
    };

    // Padding definition
    // Encryption with padding must ensure that MAC does not end with 0x00
    // Padding is signaled by a 0x00 byte in the end, followed by the number of padding 0x00 bytes
    // <data_ends_with_MAC: ...0abc01230a><padding: 0x0000000000000><padsize (u16): 0x0000><sentinel: 0x00>
    // Special cases: 1, 2, 3 0x00
    let mut padding;

    let payload = match last_4 {
        (0u8, size1, size2, 0u8) => {
            let expected = [*size1, *size2];
            let v = BigEndian::read_u16(&expected);
            if v > 4 {
                padding = vec![0u8; v as usize - 4];
                padding.extend_from_slice(&[0u8, *size1, *size2, 0u8]);
                Payload {
                    msg: &data[..data.len() - v as usize],
                    aad: &padding,
                }
            } else {
                Payload {
                    msg: data,
                    aad: b"",
                }
            }
        }
        (_, 0u8, 0u8, 0u8) => Payload {
            msg: &data[..data.len() - 3],
            aad: &[0u8, 0u8, 0u8],
        },
        (_, _, 0u8, 0u8) => Payload {
            msg: &data[..data.len() - 2],
            aad: &[0u8, 0u8],
        },
        (_, _, _, 0u8) => Payload {
            msg: &data[..data.len() - 1],
            aad: &[0u8],
        },
        _ => Payload {
            msg: data,
            aad: b"",
        },
    };

    let cipher = ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| ChaChaPoly1305Error::CipherInitError(e.to_string()))?;

    cipher
        .decrypt(nonce_slice.into(), payload)
        .map(|plaintext| plaintext.into())
        .map_err(|e| ChaChaPoly1305Error::DecryptionError(e.to_string()))
}

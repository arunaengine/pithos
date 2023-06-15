use crate::transformer::Transformer;
use anyhow::anyhow;
use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::AeadCore;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;

pub struct ChaCha20Enc {
    input_buf: BytesMut,
    output_buf: BytesMut,
    add_padding: bool,
    encryption_key: Vec<u8>,
    finished: bool,
}

impl ChaCha20Enc {
    #[allow(dead_code)]
    pub fn new(add_padding: bool, enc_key: Vec<u8>) -> Result<Self> {
        Ok(ChaCha20Enc {
            input_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            output_buf: BytesMut::with_capacity(2 * ENCRYPTION_BLOCK_SIZE),
            add_padding,
            finished: false,
            encryption_key: enc_key,
        })
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Enc {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        // Only write if the buffer contains data and the current process is not finished

        if !buf.is_empty() {
            self.input_buf.put(buf.split());
        }
        if self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
            while self.input_buf.len() / ENCRYPTION_BLOCK_SIZE > 0 {
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split(),
                    b"",
                    &self.encryption_key,
                )?)
            }
        } else if finished && !self.finished {
            if self.input_buf.is_empty() {
                self.finished = true;
            } else if self.add_padding {
                self.finished = true;
                let data = self.input_buf.split();
                let padding =
                    generate_padding(ENCRYPTION_BLOCK_SIZE - (data.len() % ENCRYPTION_BLOCK_SIZE))?;
                self.output_buf
                    .put(encrypt_chunk(&data, &padding, &self.encryption_key)?);
                self.output_buf.put(padding.as_ref());
            } else {
                self.finished = true;
                self.output_buf.put(encrypt_chunk(
                    &self.input_buf.split(),
                    b"",
                    &self.encryption_key,
                )?)
            }
        };
        buf.put(self.output_buf.split());
        Ok(self.finished && self.input_buf.is_empty() && self.output_buf.is_empty())
    }
}

pub fn encrypt_chunk(msg: &[u8], aad: &[u8], enc: &[u8]) -> Result<Bytes> {
    let mut nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut bytes = BytesMut::new();
    let pload = Payload { msg, aad };
    let cipher = ChaCha20Poly1305::new_from_slice(enc)
        .map_err(|_| anyhow!("[CHACHA_ENCRYPT] Unable to initialize cipher from key"))?;
    let mut result = cipher
        .encrypt(&nonce, pload)
        .map_err(|_| anyhow!("[CHACHA_ENCRYPT] Unable to encrypt chunk"))?;

    while result.ends_with(&[0u8]) {
        let pload = Payload { msg, aad };
        nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        result = cipher
            .encrypt(&nonce, pload)
            .map_err(|_| anyhow!("[CHACHA_ENCRYPT] Unable to encrypt chunk"))?;
    }

    bytes.put(nonce.as_ref());
    bytes.put(result.as_ref());
    bytes.put(aad);

    Ok(bytes.freeze())
}

pub fn generate_padding(size: usize) -> Result<Vec<u8>> {
    match size {
        0 => Ok(Vec::new()),
        1 => Ok(vec![0u8]),
        2 => Ok(vec![0u8, 0u8]),
        3 => Ok(vec![0u8, 0u8, 0u8]),
        size => {
            let mut padding = vec![0u8; size - 3];
            let as_u16 = u16::try_from(size)?;
            padding.extend(as_u16.to_be_bytes());
            padding.push(0u8);
            Ok(padding)
        }
    }
}

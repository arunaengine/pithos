use crate::helpers::notifications::{Message, Notifier};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use tracing::error;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaChaResilient {
    input_buffer: BytesMut,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    decryption_key: [u8; 32],
    chunk_lengths: Vec<u64>, // File data+meta keys
    skip_me: bool,
}

impl ChaChaResilient {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new_with_lengths(key: [u8; 32], lengths: Vec<u64>) -> Self {
        let mut residues = HashMap::new();

        // Always start with the default CIPHER_SEGMENT_SIZE
        residues.insert(CIPHER_SEGMENT_SIZE as u64, u32::MAX);

        for lengths in &lengths {
            let residue = *lengths % CIPHER_SEGMENT_SIZE as u64;
            if residue != 0 {
                let entry = residues.entry(*lengths).or_insert(1);
                *entry += 1;
            }
        }

        // Sort residues by occurrences
        let in_order_residues: Vec<u64> = residues
            .into_iter()
            .sorted_by(|a, b| b.1.cmp(&a.1))
            .map(|(k, _)| k)
            .collect();

        ChaChaResilient {
            input_buffer: BytesMut::with_capacity(5 * CIPHER_SEGMENT_SIZE),
            decryption_key: key,
            skip_me: false,
            notifier: None,
            msg_receiver: None,
            chunk_lengths: in_order_residues,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => return Ok(true),
                    Ok(Message::Skip) => {
                        self.skip_me = true;
                    }
                    Ok(_) => {}
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Closed) => {
                        error!("Message receiver closed");
                        return Err(anyhow!("Message receiver closed"));
                    }
                }
            }
        }
        Ok(false)
    }
}

#[async_trait::async_trait]
impl Transformer for ChaChaResilient {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::ChaCha20Decrypt, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        if self.skip_me {
            debug!("skipped");
            return Ok(());
        }

        let Ok(finished) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if !buf.is_empty() {
            self.input_buffer.put(buf.split());
        }
        let mut counter = 0;
        let mut current = CIPHER_SEGMENT_SIZE as u64;
        loop {
            if self.input_buffer.is_empty() {
                break;
            }
            let next_chunksize = if let Some(len) = self.chunk_lengths.get(counter) {
                len.clone()
            } else {
                if current < 15 + 1 {
                    return Err(anyhow!("Unable to process any more chunks abort!"));
                }
                current -= 1;
                current + 1
            };

            if self.input_buffer.len() < next_chunksize as usize {
                if finished {
                    // If we are finished we must advance the chunklength calculator
                    // until we are below the buffer size, since it will not grow anymore
                    counter += 1;
                    continue;
                } else {
                    break;
                }
            }

            match decrypt_chunk(
                &self.input_buffer.split_to(next_chunksize as usize),
                &self.decryption_key,
            ) {
                Ok(bytes) => {
                    buf.put(bytes);
                    if self.input_buffer.len() > CIPHER_SEGMENT_SIZE {
                        // Reset and continue
                        counter = 0;
                        current = CIPHER_SEGMENT_SIZE as u64;
                        continue;
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    counter += 1;
                    error!(
                        ?e,
                        "Error decrypting chunk tested with size {}", next_chunksize
                    );
                    continue;
                }
            };
        }

        if finished && self.input_buffer.is_empty() {
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}

#[tracing::instrument(level = "trace", skip(chunk, decryption_key))]
#[inline]
pub fn decrypt_chunk(chunk: &[u8], decryption_key: &[u8; 32]) -> Result<Bytes> {
    if chunk.len() < 15 {
        error!(len = chunk.len(), "Unexpected chunk size < 15");
        bail!("[CHACHA_DECRYPT] Unexpected chunk size < 15")
    }

    let (nonce_slice, data) = chunk.split_at(12);

    if nonce_slice.len() != 12 {
        error!(len = nonce_slice.len(), "Invalid nonce size");
        bail!("[CHACHA_DECRYPT] Invalid nonce")
    }

    let payload = Payload {
        msg: data,
        aad: b"",
    };
    Ok(ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| {
            error!(?e, "Unable to initialize decryptor");
            anyhow::anyhow!("[CHACHA_DECRYPT] Unable to initialize decryptor")
        })?
        .decrypt(nonce_slice.into(), payload)
        .map_err(|_| anyhow::anyhow!("[CHACHA_DECRYPT] Unable to decrypt chunk"))?
        .into())
}

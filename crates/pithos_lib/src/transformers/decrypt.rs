use crate::helpers::notifications::{Message, Notifier};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender, TryRecvError};
use byteorder::BigEndian;
use byteorder::ByteOrder;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use std::collections::VecDeque;
use std::sync::Arc;
use tracing::error;
use tracing::info;
use tracing::{debug, trace};

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub struct ChaCha20Dec {
    input_buffer: BytesMut,
    output_buffer: BytesMut,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    decryption_key: Option<[u8; 32]>,
    available_keys: Option<VecDeque<([u8; 32], usize)>>, // File data+meta keys
    _key_is_fixed: bool,
    finished: bool,
    backoff_counter: usize,
    skip_me: bool,
    file_idx: VecDeque<usize>,
    debug_counter: usize,
}

impl ChaCha20Dec {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            backoff_counter: 0,
            decryption_key: None,
            available_keys: None,
            _key_is_fixed: false,
            skip_me: false,
            notifier: None,
            msg_receiver: None,
            idx: None,
            file_idx: VecDeque::from([0]),
            debug_counter: 0,
        })
    }

    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new_with_fixed(key: [u8; 32]) -> Result<Self> {
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            backoff_counter: 0,
            decryption_key: Some(key),
            available_keys: None,
            _key_is_fixed: true,
            skip_me: false,
            notifier: None,
            msg_receiver: None,
            idx: None,
            file_idx: VecDeque::from([0]),
            debug_counter: 0,
        })
    }

    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new_with_fixed_list(keys: Vec<([u8; 32], usize)>) -> Result<Self> {
        Ok(ChaCha20Dec {
            input_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            output_buffer: BytesMut::with_capacity(5 * ENCRYPTION_BLOCK_SIZE),
            finished: false,
            backoff_counter: 0,
            decryption_key: Some(
                keys.first()
                    .ok_or_else(|| anyhow!("Empty key list provided"))?
                    .0,
            ),
            available_keys: Some(VecDeque::from(keys)),
            _key_is_fixed: true,
            skip_me: false,
            notifier: None,
            msg_receiver: None,
            idx: None,
            file_idx: VecDeque::from([0]),
            debug_counter: 0,
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn check_decrypt_chunk(&mut self) -> Result<()> {
        let split_len = if self.input_buffer.len() > CIPHER_SEGMENT_SIZE {
            CIPHER_SEGMENT_SIZE
        } else {
            self.input_buffer.len()
        };
        if let Some(key) = self.decryption_key {
            if !self.input_buffer.is_empty() {
                let buffer_bytes = self.input_buffer.split_to(split_len);
                let mut maybe_chunk = decrypt_chunk(&buffer_bytes, &key);
                if let Ok(chunk) = maybe_chunk {
                    self.output_buffer.put(chunk);
                    return Ok(());
                } else if let Some(k) = &self.available_keys {
                    for (key, _) in k {
                        maybe_chunk = decrypt_chunk(&buffer_bytes, key);
                        if let Ok(chunk) = maybe_chunk {
                            self.decryption_key = Some(*key);
                            self.output_buffer.put(chunk);
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn next_file(&mut self) -> Result<()> {
        if let Some(idx) = self.file_idx.pop_front() {
            if let Some(k) = self.available_keys.as_mut() {
                k.retain(|(_, i)| *i >= idx);
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::FileContext(ctx)) => {
                        self.file_idx.push_back(ctx.idx);
                        if let Some(data_key) = ctx.encryption_key.get_data_key() {
                            if let Some(key) = self.available_keys.as_mut() {
                                key.push_back((data_key.as_slice().try_into()?, ctx.idx));
                            } else {
                                self.available_keys = Some(VecDeque::from([(
                                    data_key.as_slice().try_into()?,
                                    ctx.idx,
                                )]));
                            }

                            if self.decryption_key.is_none() {
                                self.decryption_key = Some(data_key.as_slice().try_into()?);
                            }
                        }
                    }
                    Ok(Message::ShouldFlush) => return Ok((true, false)),
                    Ok(Message::Skip) => {
                        self.skip_me = true;
                    }
                    Ok(Message::Finished) => return Ok((false, true)),
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
        Ok((false, false))
    }
}

#[async_trait::async_trait]
impl Transformer for ChaCha20Dec {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::ChaCha20Decrypt, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        self.debug_counter += buf.len();

        if self.skip_me {
            debug!("skipped");
            return Ok(());
        }

        let Ok((should_flush, finished)) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if should_flush {
            self.input_buffer.put(buf.split());
            self.check_decrypt_chunk()?;
            buf.put(self.output_buffer.split().freeze());
            debug!(buf_len = buf.len(), "bytes flushed");
            self.next_file()?;
            return Ok(());
        }
        // Only write if the buffer contains data and the current process is not finished

        if !buf.is_empty() {
            self.input_buffer.put(buf.split());
        }

        if self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
            while self.input_buffer.len() / CIPHER_SEGMENT_SIZE > 0 {
                self.check_decrypt_chunk()?;
            }
        }
        if finished && !self.finished {
            trace!(finished, self.finished);
            if !self.input_buffer.is_empty() {
                if self.input_buffer.len() > 28 {
                    self.finished = true;
                    self.check_decrypt_chunk()?;
                } else {
                    info!(
                        len = self.input_buffer.len(),
                        self.backoff_counter, "Buffer too small, backoff"
                    );
                    self.backoff_counter += 1;
                    if self.backoff_counter > 10 {
                        self.input_buffer.clear();
                        self.finished = true;
                        error!(
                            len = self.input_buffer.len(),
                            "Buffer too small, backoff reached, discarding rest"
                        );
                        bail!("Buffer too small, backoff reached, would discard rest");
                    }
                }
            } else {
                self.finished = true;
            }
        };
        buf.put(self.output_buffer.split().freeze());
        if self.finished && self.input_buffer.is_empty() && self.output_buffer.is_empty() {
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
    Ok(ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| {
            error!(?e, "Unable to initialize decryptor");
            anyhow::anyhow!("[CHACHA_DECRYPT] Unable to initialize decryptor")
        })?
        .decrypt(nonce_slice.into(), payload)
        .map_err(|_| anyhow::anyhow!("[CHACHA_DECRYPT] Unable to decrypt chunk"))?
        .into())
}

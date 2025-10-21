use crate::helpers::frames::create_skippable_padding_frame;
use crate::helpers::notifications::Notifier;
use crate::helpers::notifications::{CompressionInfo, Message};
use crate::helpers::structs::FileContext;
use crate::helpers::structs::ProbeResult;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use crate::transformers::encrypt::encrypt_chunk;
use anyhow::anyhow;
use anyhow::Result;
use async_channel::Receiver;
use async_channel::Sender;
use async_channel::TryRecvError;
use async_compression::tokio::write::ZstdEncoder;
use bytes::BytesMut;
use bytes::{BufMut, Bytes};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::error;

const CHUNK: u32 = 65_536;

struct CurrentFile {
    idx: usize,
    raw_size_full: u64,
    compressed_size: u64,
    multiplier: u32,
    encryption_key: Option<[u8; 32]>,
    compression: ProbeResult,
    raw_size_current_chunk: u32,
    chunk_sizes: Vec<u32>,
}

impl Default for CurrentFile {
    fn default() -> Self {
        CurrentFile {
            idx: 0,
            raw_size_full: 0,
            compressed_size: 0,
            multiplier: 1,
            encryption_key: None,
            compression: ProbeResult::Unknown,
            raw_size_current_chunk: 0,
            chunk_sizes: Vec::new(),
        }
    }
}

impl From<CurrentFile> for CompressionInfo {
    fn from(val: CurrentFile) -> Self {
        CompressionInfo {
            idx: val.idx,
            raw_size: val.raw_size_full,
            compressed_size: val.compressed_size,
            compression: val.compression == ProbeResult::Compression,
            chunk_infos: Some(val.chunk_sizes),
        }
    }
}

impl CurrentFile {
    pub fn advance(&mut self, size: usize) {
        self.raw_size_full += size as u64;
        self.raw_size_current_chunk += size as u32;
    }

    pub fn next_chunk(&mut self) {
        self.chunk_sizes.push(self.raw_size_current_chunk);
        self.raw_size_current_chunk = 0;
    }
}

impl From<FileContext> for CurrentFile {
    fn from(ctx: FileContext) -> Self {
        CurrentFile {
            idx: ctx.idx,
            raw_size_full: 0,
            compressed_size: 0,
            multiplier: ctx.chunk_multiplier.unwrap_or(1),
            encryption_key: ctx.encryption_key.get_data_key(),
            compression: ProbeResult::Unknown,
            raw_size_current_chunk: 0,
            chunk_sizes: Vec::new(),
        }
    }
}

pub struct PithosTransformer {
    internal_buf: ZstdEncoder<Vec<u8>>,
    capture_buf: BytesMut,
    file_queue: VecDeque<CurrentFile>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl PithosTransformer {
    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new() -> Self {
        PithosTransformer {
            internal_buf: ZstdEncoder::new(Vec::with_capacity(CHUNK as usize)),
            capture_buf: BytesMut::with_capacity(CHUNK as usize),
            file_queue: VecDeque::new(),
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace")]
    #[allow(dead_code)]
    pub fn new_with_default_ctx() -> Self {
        PithosTransformer {
            internal_buf: ZstdEncoder::new(Vec::with_capacity(CHUNK as usize)),
            capture_buf: BytesMut::with_capacity(CHUNK as usize),
            file_queue: VecDeque::from([CurrentFile::default()]),
            notifier: None,
            msg_receiver: None,
            idx: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => {
                        return Ok((true, true));
                    }
                    Ok(Message::ShouldFlush) => {
                        return Ok((false, true));
                    }
                    Ok(Message::FileContext(ctx)) => {
                        self.file_queue.push_back(ctx.into());
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
        Ok((false, false))
    }

    #[tracing::instrument(level = "trace", skip(bytes))]
    async fn probe_compression(bytes: &[u8]) -> Result<bool> {
        let original_size = bytes.len();
        let mut compressor = ZstdEncoder::new(Vec::with_capacity(original_size + 100));
        compressor.write_all(bytes).await?;
        compressor.shutdown().await?;
        if (original_size as f64 * 0.875) as usize > compressor.get_ref().len() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn has_encryption_key(&self) -> bool {
        if let Some(first) = self.file_queue.front() {
            return first.encryption_key.is_some();
        }
        false
    }

    fn set_compression(&mut self, probe_result: bool) {
        if let Some(first) = self.file_queue.front_mut() {
            if probe_result {
                first.compression = ProbeResult::Compression;
            } else {
                first.compression = ProbeResult::NoCompression;
            }
        }
    }

    async fn try_probe_compression(&mut self, finished: bool) -> Result<Option<ProbeResult>> {
        let current_compression = self
            .file_queue
            .front()
            .map(|f| f.compression.clone())
            .unwrap_or_default();
        if let ProbeResult::Unknown = current_compression {
            let probe_result = if self.capture_buf.len() > 8192 {
                Self::probe_compression(self.capture_buf.get(0..8192).unwrap_or_default()).await?
            } else if finished {
                Self::probe_compression(
                    self.capture_buf
                        .get(0..self.capture_buf.len())
                        .unwrap_or_default(),
                )
                .await?
            } else {
                return Ok(None);
            };

            let probe_result_ctx = if probe_result {
                ProbeResult::Compression
            } else {
                ProbeResult::NoCompression
            };
            self.set_compression(probe_result);
            return Ok(Some(probe_result_ctx));
        }
        Ok(Some(current_compression))
    }

    async fn smart_compress(&mut self, flush: bool) -> Result<Bytes> {
        let mut current_size: usize = self.internal_buf.get_ref().len();
        let final_size = CHUNK
            * self
                .file_queue
                .front()
                .map(|f| f.multiplier)
                .unwrap_or_else(|| 1);
        let mut to_read: usize = (final_size as usize)
            .saturating_sub(current_size)
            .saturating_sub(20);

        let mut result = BytesMut::new();
        while !self.capture_buf.is_empty() {
            let bytes = if to_read > self.capture_buf.len() {
                self.advance_file(self.capture_buf.len());
                self.capture_buf.split()
            } else {
                self.advance_file(to_read);
                self.capture_buf.split_to(to_read)
            };

            self.internal_buf.write_all(&bytes).await?;
            self.internal_buf.flush().await?;
            current_size = self.internal_buf.get_ref().len();
            to_read = (final_size as usize)
                .saturating_sub(current_size)
                .saturating_sub(20);
            if to_read == 0 {
                self.next_chunk();
                self.internal_buf.shutdown().await?;
                let internal_buf_len = self.internal_buf.get_ref().len();
                // Skippable frame to x*65Kib
                let remaining = CHUNK as usize - (internal_buf_len % CHUNK as usize);
                result.put(self.internal_buf.get_ref().as_ref());
                result.put(create_skippable_padding_frame(remaining)?.as_ref());
                self.internal_buf = ZstdEncoder::new(Vec::with_capacity(CHUNK as usize));
            }
        }

        if flush {
            self.next_chunk();
            self.internal_buf.shutdown().await?;
            result.put(self.internal_buf.get_ref().as_ref());
            self.internal_buf = ZstdEncoder::new(Vec::with_capacity(CHUNK as usize));
        }

        Ok(result.freeze())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn add_compressed_bytes(&mut self, bytes: usize) {
        if let Some(first) = self.file_queue.front_mut() {
            first.compressed_size += bytes as u64;
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn advance_file(&mut self, advance: usize) {
        if let Some(first) = self.file_queue.front_mut() {
            first.advance(advance);
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn next_chunk(&mut self) {
        if let Some(first) = self.file_queue.front_mut() {
            first.next_chunk();
        }
    }
}

#[async_trait::async_trait]
impl Transformer for PithosTransformer {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::ZstdCompressor, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut BytesMut) -> Result<()> {
        let Ok((finished, flush)) = self.process_messages() else {
            return Err(anyhow!("[PithosTransformer] Error processing messages"));
        };
        self.capture_buf.put(buf.split());

        // Evaluate compression state
        let Some(probe_result) = self.try_probe_compression(finished).await? else {
            return Ok(());
        };

        // Compression
        let compressed_bytes = if let ProbeResult::Compression = probe_result {
            // "Smart" compress
            self.smart_compress(flush || finished).await?
        } else {
            let to_read = if flush {
                self.capture_buf.len()
            } else {
                (self.capture_buf.len() / CHUNK as usize) * CHUNK as usize
            };
            self.advance_file(to_read);
            self.capture_buf.split_to(to_read).freeze()
        };

        // Encryption
        if let Some(encryption_key) = self
            .file_queue
            .front()
            .map(|f| f.encryption_key)
            .unwrap_or_default()
        {
            // Encrypt in chunks
            for chunk in compressed_bytes.chunks(CHUNK as usize) {
                buf.put(encrypt_chunk(chunk, b"", encryption_key.as_slice(), true)?)
            }
        } else {
            buf.put(compressed_bytes);
        }
        self.add_compressed_bytes(buf.len());

        if flush || finished {
            if let Some(notifier) = &self.notifier {
                if let Some(file) = self.file_queue.pop_front() {
                    notifier.send_all_type(
                        TransformerType::FooterGenerator,
                        Message::CompressionInfo(file.into()),
                    )?;
                }
                if finished {
                    notifier.send_next(
                        self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                        Message::Finished,
                    )?;
                }
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

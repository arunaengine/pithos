use std::sync::Arc;

use crate::notifications::Message;
use crate::notifications::Notifier;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::{anyhow, Result};
use async_channel::Receiver;
use async_channel::Sender;
use async_channel::TryRecvError;
use async_compression::tokio::write::ZstdDecoder;
use bytes::BufMut;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::error;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct ZstdDec {
    internal_buf: ZstdDecoder<Vec<u8>>,
    prev_buf: BytesMut,
    skip_me: bool,
    finished: bool,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl ZstdDec {
    #[tracing::instrument(level = "trace", skip())]
    #[allow(dead_code)]
    pub fn new() -> ZstdDec {
        ZstdDec {
            internal_buf: ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            skip_me: false,
            finished: false,
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
                    Ok(Message::ShouldFlush) => return Ok((true, false)),
                    Ok(Message::Finished) => return Ok((false, true)),
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
        Ok((false, false))
    }
}

impl Default for ZstdDec {
    #[tracing::instrument(level = "trace", skip())]
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for ZstdDec {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::ZstdDecompressor, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        dbg!(buf.len());
        let Ok((should_flush, finished)) = self.process_messages() else {
            return Err(anyhow!("Error processing messages"));
        };

        if self.skip_me {
            debug!("skipped zstd decoder");
            return Ok(());
        }
        if should_flush {
            debug!("flushed zstd decoder");
            self.internal_buf.write_all_buf(buf).await?;
            self.internal_buf.shutdown().await?;
            self.prev_buf.put(self.internal_buf.get_ref().as_slice());
            self.internal_buf = ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
            buf.put(self.prev_buf.split().freeze());
            return Ok(());
        }

        // Only write if the buffer contains data and the current process is not finished
        if !buf.is_empty() && !self.finished {
            self.internal_buf.write_buf(buf).await?;
            while !buf.is_empty() {
                self.internal_buf.shutdown().await?;
                self.prev_buf.put(self.internal_buf.get_ref().as_slice());
                self.internal_buf = ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
                self.internal_buf.write_buf(buf).await?;
            }
        }

        if !self.finished && buf.is_empty() && finished {
            debug!("finish zstd decoder");
            self.internal_buf.shutdown().await?;
            self.prev_buf.put(self.internal_buf.get_ref().as_slice());
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
            self.finished = true;
        }

        buf.put(self.prev_buf.split().freeze());
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_zstd_decoder_with_skip() {
        let mut decoder = ZstdDec::new();
        let mut buf = BytesMut::new();
        let expected = hex::decode(format!(
            "28b52ffd00582900003132333435502a4d18eaff{}",
            "00".repeat(65516)
        ))
        .unwrap();
        buf.put(expected.as_slice());
        decoder.process_bytes(&mut buf).await.unwrap();
        // Expect 65kb size
        assert_eq!(buf.len(), 5);
        assert_eq!(buf, b"12345".as_slice());
    }

    #[tokio::test]
    async fn test_zstd_encoder_without_skip() {
        let mut decoder = ZstdDec::new();
        let mut buf = BytesMut::new();
        let expected = hex::decode("28b52ffd00582900003132333435").unwrap();
        buf.put(expected.as_slice());
        decoder.process_bytes(&mut buf).await.unwrap();
        // Expect 65kb size
        assert_eq!(buf.len(), 5);
        assert_eq!(buf, b"12345".as_slice());
    }
}

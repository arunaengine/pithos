use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdDecoder;
use bytes::BufMut;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

use crate::transformer::AddTransformer;
use crate::transformer::Stats;
use crate::transformer::Transformer;

const RAW_FRAME_SIZE: usize = 5_242_880;
const CHUNK: usize = 65_536;

pub struct ZstdDec<'a> {
    internal_buf: ZstdDecoder<Vec<u8>>,
    prev_buf: BytesMut,
    size_counter: usize,
    finished: bool,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> ZstdDec<'a> {
    #[allow(dead_code)]
    pub fn new() -> ZstdDec<'a> {
        ZstdDec {
            internal_buf: ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK)),
            prev_buf: BytesMut::with_capacity(RAW_FRAME_SIZE + CHUNK),
            size_counter: 0,
            finished: false,
            next: None,
        }
    }
}

impl<'a> AddTransformer<'a> for ZstdDec<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for ZstdDec<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        // Only write if the buffer contains data and the current process is not finished
        if buf.len() != 0 && !self.finished {
            self.size_counter += buf.len();
            self.internal_buf.write_buf(buf).await?;
        }

        if self.size_counter > CHUNK * 20 {
            self.internal_buf.shutdown().await?;
            self.prev_buf.put(self.internal_buf.get_ref().as_slice());
            self.internal_buf = ZstdDecoder::new(Vec::with_capacity(RAW_FRAME_SIZE + CHUNK));
        }

        if !self.finished && buf.len() == 0 && finished {
            self.finished = true;
        }

        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            let mut bytes = if self.prev_buf.len() / CHUNK > 0 {
                self.prev_buf.split_to(CHUNK).freeze()
            } else {
                self.prev_buf.split().freeze()
            };
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(&mut bytes, self.finished && self.prev_buf.len() == 0)
                .await
        } else {
            Err(anyhow!(
                "This compressor is designed to always contain a 'next'"
            ))
        }
    }
    async fn get_info(&mut self, _is_last: bool) -> Result<Vec<Stats>> {
        todo!();
    }
}

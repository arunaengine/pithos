use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use async_compression::tokio::write::GzipEncoder;
use bytes::BufMut;
use tokio::io::AsyncWriteExt;

const RAW_FRAME_SIZE: usize = 5_242_880;

pub struct GzipEnc {
    internal_buf: GzipEncoder<Vec<u8>>,
    size_counter: usize,
}

impl GzipEnc {
    #[allow(dead_code)]
    pub fn new() -> Self {
        GzipEnc {
            internal_buf: GzipEncoder::new(Vec::with_capacity(RAW_FRAME_SIZE)),
            size_counter: 0,
        }
    }
}

impl Default for GzipEnc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for GzipEnc {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        self.size_counter += buf.len();
        self.internal_buf.write_all_buf(buf).await?;
        // Create a new frame if buf would increase size_counter to more than RAW_FRAME_SIZE
        if self.size_counter > RAW_FRAME_SIZE {
            self.internal_buf.flush().await?;
            buf.put(self.internal_buf.get_ref().as_slice());
            self.internal_buf.get_mut().clear();
            self.size_counter = 0;
        }

        if finished && self.size_counter != 0 {
            self.internal_buf.shutdown().await?;
            buf.put(self.internal_buf.get_ref().as_slice());
            self.size_counter = 0;
        }

        Ok(finished)
    }

    fn get_type(&self) -> TransformerType {
        TransformerType::GzipCompressor
    }
}

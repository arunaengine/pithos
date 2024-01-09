use crate::notifications;
use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::anyhow;
use anyhow::Result;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::BufMut;
use bytes::{Bytes, BytesMut};
use tracing::debug;
use tracing::error;

pub struct FooterGenerator {
    finished: bool,
    external_info: BytesMut,
}

impl FooterGenerator {
    #[tracing::instrument(level = "trace", skip(external_info))]
    #[allow(dead_code)]
    pub fn new(external_info: Option<Vec<u8>>) -> FooterGenerator {
        debug!(has_info = external_info.is_some(), "new footergenerator");
        FooterGenerator {
            finished: false,
            external_info: match external_info {
                Some(i) => i.as_slice().into(),
                _ => BytesMut::new(),
            },
        }
    }
}

#[async_trait::async_trait]
impl Transformer for FooterGenerator {
    #[tracing::instrument(level = "trace", skip(self, buf, finished))]
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        _: bool,
    ) -> Result<bool> {
        if buf.is_empty() && !self.finished && finished {
            if self.external_info.is_empty() {
                error!("Missing chunk info");
                return Err(anyhow!("Missing chunk info"));
            }
            buf.put(create_skippable_footer_frame(self.external_info.to_vec())?);
            debug!("added footer");
            self.finished = true;
        }
        Ok(self.finished)
    }
    #[tracing::instrument(level = "trace", skip(self, message))]
    async fn notify(&mut self, message: &Message) -> Result<Response> {
        match message.target {
            TransformerType::FooterGenerator => {
                if let notifications::MessageData::Footer(data) = &message.data {
                    debug!(num_chunks = ?data.chunks.len(), "received footer info message");
                    self.external_info.put(data.chunks.as_ref())
                }
            }
            TransformerType::All => {}
            _ => {
                error!(?message, "Received invalid message");
                return Err(anyhow!("Received invalid message"));
            }
        }
        Ok(Response::Ok)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    #[inline]
    fn get_type(&self) -> TransformerType {
        TransformerType::FooterGenerator
    }
}

#[tracing::instrument(level = "trace", skip(footer_list))]
#[inline]
fn create_skippable_footer_frame(mut footer_list: Vec<u8>) -> Result<Bytes> {
    // 65_536 framesize minus 12 bytes for header
    // 1. Magic bytes (4)
    // 2. Size (4) -> The number 65536 - 8 bytes for needed skippable frame header
    // 3. BlockTotal -> footer_list.len() + frames
    // Up to 65_536 - 12 footer entries for one frame
    let total: u32 = footer_list.iter().map(|e| *e as u32).sum();

    let frames = if footer_list.len() < (65_536 - 12) {
        1
    } else {
        2
    };
    // Create a frame_header
    let mut frame = hex::decode(format!("5{frames}2A4D18"))?;

    if frames == 1 {
        let target_size = 65_536 - footer_list.len() - 12;
        //
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, 65_536 - 8)?;
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, total + frames)?;

        if let Some(e) = footer_list.last_mut() {
            *e += 1
        };
        for size in footer_list {
            WriteBytesExt::write_u8(&mut frame, size)?;
            assert!(size < 84)
        }
        frame.extend(vec![0; target_size]);
        assert!(frame.len() == 65_536);
        Ok(Bytes::from(frame))
    } else {
        // Magic frame "size"
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, 65_536 - 8)?;
        // Footerlist count
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, total + frames)?;

        if let Some(e) = footer_list.last_mut() {
            *e += 2
        };
        // Blocklist
        for size in &footer_list[..(65_536 - 12)] {
            WriteBytesExt::write_u8(&mut frame, *size)?;
            assert!(*size < 84)
        }
        assert!(frame.len() == 65_536);
        // Repeat the header
        frame.put(hex::decode(format!("5{frames}2A4D18"))?.as_slice());
        // Magic frame "size"
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, 65_536 - 8)?;
        // Repeat footerlist count
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, total + frames)?;

        // Write the whole footerlist
        for size in &footer_list[(65_536 - 12)..] {
            WriteBytesExt::write_u8(&mut frame, *size)?;
            assert!(*size < 84)
        }

        let target_size = footer_list.len() - 12 - 65_536;

        frame.extend(vec![0; target_size]);
        assert!(frame.len() == 65_536 * 2);
        Ok(Bytes::from(frame))
    }
}
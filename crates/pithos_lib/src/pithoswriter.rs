use crate::streamreadwrite::GenericStreamReadWriter;
use crate::transformer::{FileContext, Sink, Transformer};
use crate::transformers::encrypt::ChaCha20Enc;
use crate::transformers::footer::FooterGenerator;
use crate::transformers::hashing_transformer::HashingTransformer;
use crate::transformers::zstd_comp::ZstdEnc;
use anyhow::Result;
use bytes::Bytes;
use digest::Digest;
use futures::Stream;
use md5::Md5;
use sha1::Sha1;

pub struct PithosWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
        + Unpin
        + Send
        + Sync,
> {
    stream_read_writer: GenericStreamReadWriter<'a, R>,
    file_context: FileContext,
    metadata: Option<String>, // Validated JSON
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > PithosWriter<'a, R>
{
    #[tracing::instrument(level = "trace", skip(input_stream, sink))]
    pub fn new<T: Transformer + Sink + Send + Sync + 'a>(
        input_stream: R,
        sink: T,
        file_context: FileContext,
        metadata: Option<String>,
    ) -> Result<Self> {
        let mut stream_read_writer = GenericStreamReadWriter::new_with_sink(input_stream, sink);

        // Hashes
        let (md5_transformer, md5_receiver) = HashingTransformer::new(Md5::new());
        let (sha1_transformer, sha1_receiver) = HashingTransformer::new(Sha1::new());
        stream_read_writer = stream_read_writer.add_transformer(md5_transformer);
        stream_read_writer = stream_read_writer.add_transformer(sha1_transformer);

        if file_context.compression {
            stream_read_writer = stream_read_writer.add_transformer(ZstdEnc::new(false));
        }
        if let Some(encryption_key) = &file_context.encryption_key {
            stream_read_writer = stream_read_writer
                .add_transformer(ChaCha20Enc::new(false, encryption_key.clone())?);
        }
        stream_read_writer = stream_read_writer.add_transformer(FooterGenerator::new(None));

        Ok(PithosWriter {
            stream_read_writer,
            file_context,
            metadata,
        })
    }
}